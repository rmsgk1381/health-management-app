from datetime import datetime, timedelta, timezone
from uuid import UUID

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
