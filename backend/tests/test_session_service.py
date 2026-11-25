from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from models import Session as AuthSession
from security import hash_session_token
from session_service import (
    create_session,
    find_session_by_token,
    is_session_valid,
    update_session_activity,
    delete_invalid_sessions,
)
from settings import settings
from user_service import register_user


# 생성한 세션의 DB 저장값이 원문 토큰과 다르고 해당 토큰의 해시와 일치하는지 확인한다.
def test_create_session_stores_token_hash(postgres_db):
    user = register_user(
        postgres_db, "step19.session@example.com", "testpassword"
    )
    token = create_session(postgres_db, user.id)
    saved_session = postgres_db.scalar(
        select(AuthSession).where(AuthSession.user_id == user.id)
    )
    assert saved_session is not None
    assert saved_session.session_token_hash == hash_session_token(token)
    assert saved_session.session_token_hash != token

# 설정한 유효기간을 기준으로 세션의 만료 시각이 저장되는지 확인한다.
def test_create_session_uses_configured_expiration(postgres_db, monkeypatch):
    ttl = 3600
    monkeypatch.setattr(settings, "SESSION_ABSOLUTE_TIMEOUT_SECONDS", ttl)

    user = register_user(
            postgres_db, "step19.session@example.com", "testpassword"
        )
    
    before = datetime.now(timezone.utc)
    create_session(postgres_db, user.id)
    after = datetime.now(timezone.utc)

    saved_session = postgres_db.scalar(
        select(AuthSession).where(AuthSession.user_id == user.id)
    )

    assert saved_session is not None
    assert (
        before + timedelta(seconds=ttl)
        <= saved_session.expires_at
        <= after + timedelta(seconds=ttl)
    )

# DB 저장 실패를 롤백한 뒤 같은 DB 세션으로 정상 세션을 생성할 수 있는지 확인한다.
def test_create_session_rolls_back_on_database_error(postgres_db):
    user = register_user(
                postgres_db, "step19.session@example.com", "testpassword"
            )
    with pytest.raises(IntegrityError):
        create_session(postgres_db, uuid4())

    token = create_session(postgres_db, user.id)
    saved_session = postgres_db.scalar(
        select(AuthSession).where(AuthSession.user_id == user.id)
    )

    assert saved_session is not None
    assert saved_session.session_token_hash == hash_session_token(token)

# 활성·폐기·절대 만료·유휴 만료 상태를 각각 올바르게 판정하는지 확인한다.
@pytest.mark.parametrize("state", ["active", "revoked", "absolute", "idle"])
def test_is_session_valid_checks_all_expiration_conditions(state):
    now = datetime.now(timezone.utc)
    session = AuthSession(
        user_id=uuid4(),
        session_token_hash="test-hash",
        last_seen_at=now - timedelta(days=1),
        expires_at=now + timedelta(days=1),
        revoked_at=None,
    )

    if state == "revoked":
        session.revoked_at = now - timedelta(minutes=1)
    elif state == "absolute":
        session.expires_at = now - timedelta(minutes=1)
    elif state == "idle":
        session.last_seen_at = now - timedelta(days=8)

    assert is_session_valid(session, now) is (state == "active")

# 유효 요청의 활동 시각이 DB에 저장되는지 확인한다.
def test_update_session_activity_persists_last_seen_at(postgres_db):
    user = register_user(postgres_db, "step20.activity@example.com", "testpassword")
    token = create_session(postgres_db, user.id)
    session = find_session_by_token(postgres_db, token)
    assert session is not None

    now = datetime.now(timezone.utc)
    update_session_activity(postgres_db, session, now)
    postgres_db.refresh(session)

    assert session.last_seen_at == now

# 원문 토큰으로 저장된 세션을 찾아 DB의 해시와 비교하는지 확인한다.
def test_find_session_by_token_returns_matching_session(postgres_db):
    user = register_user(postgres_db, "step20.lookup@example.com", "testpassword")
    token = create_session(postgres_db, user.id)

    found_session = find_session_by_token(postgres_db, token)

    assert found_session is not None
    assert found_session.user_id == user.id

# 사용자의 폐기·절대 만료·유휴 만료 세션만 삭제하고 유효 세션은 보존하는지 확인한다.
def test_delete_invalid_sessions_preserves_active_session(postgres_db):
    now = datetime.now(timezone.utc)
    user = register_user(
        postgres_db, "step21.cleanup@example.com", "testpassword"
    )

    tokens = [create_session(postgres_db, user.id) for _ in range(4)]
    sessions = [find_session_by_token(postgres_db, token) for token in tokens]
    active, revoked, absolute_expired, idle_expired = sessions

    assert active is not None
    assert revoked is not None
    assert absolute_expired is not None
    assert idle_expired is not None

    revoked.revoked_at = now - timedelta(minutes=1)
    absolute_expired.expires_at = now - timedelta(minutes=1)
    idle_expired.last_seen_at = now - timedelta(
        seconds=settings.SESSION_IDLE_TIMEOUT_SECONDS + 1
    )
    postgres_db.commit()

    delete_invalid_sessions(postgres_db, user.id, now)
    remaining = postgres_db.scalars(
        select(AuthSession).where(AuthSession.user_id == user.id)
    ).all()

    assert len(remaining) == 1
    assert remaining[0].id == active.id