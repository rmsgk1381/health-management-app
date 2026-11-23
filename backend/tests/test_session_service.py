from sqlalchemy import select

from models import Session as AuthSession
from security import hash_session_token
from session_service import create_session
from user_service import register_user

from datetime import datetime, timedelta, timezone
from settings import settings

import pytest
from uuid import uuid4
from sqlalchemy.exc import IntegrityError

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
