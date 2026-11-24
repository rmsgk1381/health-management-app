from datetime import datetime, timedelta, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError

from models import Session as AuthSession
from security import generate_session_token, hash_session_token
from settings import settings

def create_session(db: Session, user_id: UUID) -> str:
    token = generate_session_token()
    hashed_token = hash_session_token(token)
    expires_at = datetime.now(timezone.utc) + timedelta(
        seconds=settings.SESSION_ABSOLUTE_TIMEOUT_SECONDS
    )
    session = AuthSession(
        user_id=user_id,
        session_token_hash=hashed_token,
        expires_at=expires_at,
    )
    db.add(session)
    try:
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        raise

    return token

def find_session_by_token(db: Session, token: str) -> AuthSession | None:
    token_hash = hash_session_token(token)
    statement = select(AuthSession).where(
        AuthSession.session_token_hash == token_hash
    )
    return db.scalar(statement)

def is_session_valid(session: AuthSession, now: datetime) -> bool:
    idle_expires_at = session.last_seen_at + timedelta(
        seconds=settings.SESSION_IDLE_TIMEOUT_SECONDS
    )

    return (
        session.revoked_at is None
        and session.expires_at > now
        and idle_expires_at > now
    )

def update_session_activity(db: Session, session: AuthSession, now: datetime) -> None:
    session.last_seen_at = now
    db.commit()

def revoke_session(
    db: Session,
    session: AuthSession,
    now: datetime,
) -> None:
    session.revoked_at = now
    db.commit()