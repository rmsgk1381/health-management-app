from datetime import datetime, timezone, timedelta

from login_service import get_or_create_login_failure, record_login_failure, LoginRateLimitError, authenticate_user_with_rate_limit
from user_service import register_user, InvalidCredentialsError

from settings import settings
from sqlalchemy import select
from models import LoginFailure
from unittest.mock import Mock

import pytest
import login_service

# 새 이메일의 로그인 실패 기록이 기본값으로 생성되는지 확인한다.
def test_get_or_create_login_failure_creates_record(postgres_db):
    email = "step19.limit@example.com"
    now = datetime.now(timezone.utc)

    failure = get_or_create_login_failure(postgres_db, email, now)

    assert failure.email == email
    assert failure.window_started_at == now
    assert failure.failure_count == 0
    assert failure.blocked_until is None

# 기존 실패 기록을 다시 가져와도 횟수와 시간 정보가 유지되는지 확인한다.
def test_get_or_create_login_failure_preserves_existing_record(postgres_db):
    email = "step19.existing@example.com"
    now = datetime.now(timezone.utc)
    blocked_until = now + timedelta(seconds=60)

    failure = get_or_create_login_failure(postgres_db, email, now)
    failure.failure_count = 5
    failure.blocked_until = blocked_until
    postgres_db.flush()

    saved_failure = get_or_create_login_failure(
        postgres_db, email, now + timedelta(seconds=10)
    )

    assert saved_failure.failure_count == 5
    assert saved_failure.window_started_at == now
    assert saved_failure.blocked_until == blocked_until

# 제한 횟수 전에는 허용하고 제한 횟수에 도달하면 차단 시각을 설정한다.
def test_record_login_failure_blocks_at_limit(postgres_db, monkeypatch):
    monkeypatch.setattr(settings, "LOGIN_FAILURE_LIMIT", 5)
    monkeypatch.setattr(settings, "LOGIN_BLOCK_SECONDS", 60)

    now = datetime.now(timezone.utc)
    failure = get_or_create_login_failure(
        postgres_db, "step19.threshold@example.com", now
    )

    for expected_count in range(1, 5):
        record_login_failure(failure, now)
        assert failure.failure_count == expected_count 
        assert failure.blocked_until is None

    record_login_failure(failure, now)
    assert failure.failure_count == 5
    assert failure.blocked_until == (now + timedelta(seconds=60))

# 차단 중 재시도는 예외를 발생시키며 횟수와 차단 종료 시각을 유지한다.
def test_record_login_failure_preserves_active_block(postgres_db, monkeypatch):
    monkeypatch.setattr(settings, "LOGIN_FAILURE_LIMIT", 5)
    monkeypatch.setattr(settings, "LOGIN_BLOCK_SECONDS", 60)

    now = datetime.now(timezone.utc)
    failure = get_or_create_login_failure(
        postgres_db, "step19.blocked@example.com", now
    )

    for _ in range(5):
        record_login_failure(failure, now)

    original_blocked_until = failure.blocked_until
    retry_at = now + timedelta(seconds=10)

    with pytest.raises(LoginRateLimitError) as exc_info:
        record_login_failure(failure, retry_at)

    assert failure.failure_count == 5
    assert failure.blocked_until == original_blocked_until
    assert exc_info.value.retry_after == 50

# 차단 종료 시각에 도달하면 이전 횟수를 초기화하고 새 실패를 1회로 기록한다.
def test_record_login_failure_resets_after_block_expires(postgres_db, monkeypatch):
    monkeypatch.setattr(settings, "LOGIN_FAILURE_WINDOW_SECONDS", 900)
    monkeypatch.setattr(settings, "LOGIN_FAILURE_LIMIT", 5)
    monkeypatch.setattr(settings, "LOGIN_BLOCK_SECONDS", 60)

    now = datetime.now(timezone.utc)
    failure = get_or_create_login_failure(
        postgres_db, "step19.expired-block@example.com", now
    )

    for _ in range(5):
        record_login_failure(failure, now)

    retry_at = now + timedelta(seconds=60)
    record_login_failure(failure, retry_at)

    assert failure.failure_count == 1
    assert failure.window_started_at == retry_at
    assert failure.blocked_until is None

# 중간 실패는 집계 시작 시각을 유지하고 집계 기간 만료 시 횟수를 초기화한다.
def test_record_login_failure_resets_after_window_expires(postgres_db, monkeypatch):
    monkeypatch.setattr(settings, "LOGIN_FAILURE_WINDOW_SECONDS", 900)
    monkeypatch.setattr(settings, "LOGIN_FAILURE_LIMIT", 5)

    now = datetime.now(timezone.utc)
    failure = get_or_create_login_failure(
        postgres_db, "step19.expired-window@example.com", now
    )

    record_login_failure(failure, now)
    record_login_failure(failure, now + timedelta(seconds=100))

    assert failure.failure_count == 2
    assert failure.window_started_at == now

    retry_at = now + timedelta(seconds=900)
    record_login_failure(failure, retry_at)

    assert failure.failure_count == 1
    assert failure.window_started_at == retry_at
    assert failure.blocked_until is None

# 인증 실패 후 rollback을 호출해도 확정된 실패 기록은 유지된다.
def test_authenticate_user_with_rate_limit_persists_failure(postgres_db, monkeypatch):
    monkeypatch.setattr(settings, "LOGIN_FAILURE_LIMIT", 5)

    email = "step19.persisted@example.com"
    register_user(postgres_db, email, "testpassword")

    with pytest.raises(InvalidCredentialsError):
        authenticate_user_with_rate_limit(
            postgres_db, email, "wrong-password"
        )

    postgres_db.rollback()

    saved_failure = postgres_db.scalar(
        select(LoginFailure).where(LoginFailure.email == email)
    )

    assert saved_failure is not None
    assert saved_failure.failure_count == 1
    assert saved_failure.blocked_until is None

# 로그인 성공 시 이전 실패 기록을 삭제하고 인증된 사용자를 반환한다.
def test_authenticate_user_with_rate_limit_clears_failures_on_success(
    postgres_db, monkeypatch
):
    monkeypatch.setattr(settings, "LOGIN_FAILURE_LIMIT", 5)

    email = "step19.reset-success@example.com"
    registered_user = register_user(postgres_db, email, "testpassword")

    with pytest.raises(InvalidCredentialsError):
        authenticate_user_with_rate_limit(
            postgres_db, email, "wrong-password"
        )

    previous_failure = postgres_db.scalar(
        select(LoginFailure).where(LoginFailure.email == email)
    )
    assert previous_failure is not None
    assert previous_failure.failure_count == 1

    authenticated_user = authenticate_user_with_rate_limit(
        postgres_db, email, "testpassword"
    )

    saved_failure = postgres_db.scalar(
        select(LoginFailure).where(LoginFailure.email == email)
    )

    assert authenticated_user.id == registered_user.id
    assert saved_failure is None

# 차단 중에는 올바른 비밀번호도 거절하며 비밀번호 인증 함수를 호출하지 않는다.
def test_authenticate_user_with_rate_limit_rejects_blocked_user(
    postgres_db, monkeypatch
):
    monkeypatch.setattr(settings, "LOGIN_FAILURE_LIMIT", 5)
    monkeypatch.setattr(settings, "LOGIN_BLOCK_SECONDS", 60)

    email = "step19.blocked-user@example.com"
    register_user(postgres_db, email, "testpassword")

    for _ in range(5):
        with pytest.raises(InvalidCredentialsError):
            authenticate_user_with_rate_limit(
                postgres_db, email, "wrong-password"
            )

    auth_mock = Mock(wraps=login_service.authenticate_user_with_rate_limit)
    monkeypatch.setattr(login_service, "authenticate_user", auth_mock)

    with pytest.raises(LoginRateLimitError) as exc_info:
        authenticate_user_with_rate_limit(
            postgres_db, email, "testpassword"
        )

    auth_mock.assert_not_called()
    assert 1 <= exc_info.value.retry_after <= 60