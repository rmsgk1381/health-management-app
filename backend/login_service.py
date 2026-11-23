from datetime import datetime, timedelta, timezone
from settings import settings
from math import ceil

from models import LoginFailure, User

from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
from security import normalize_email
from user_service import authenticate_user, InvalidCredentialsError

class LoginRateLimitError(Exception):
    def __init__(self, retry_after: int) -> None:
        self.retry_after = retry_after
        super().__init__("로그인 시도 횟수를 초과했습니다.")

def get_retry_after(failure: LoginFailure | None, now: datetime) -> int:
    if failure is None or failure.blocked_until is None:
        return 0

    if failure.blocked_until is not None and failure.blocked_until > now:
        remaining_seconds = (failure.blocked_until - now).total_seconds()
        return max(0, ceil(remaining_seconds))

    return 0

def get_or_create_login_failure(
    db: Session, normalized_email: str, now: datetime) -> LoginFailure:
    statement = insert(LoginFailure).values(
        email=normalized_email,
        window_started_at=now,
    )
    statement = statement.on_conflict_do_update(
        index_elements=[LoginFailure.email],
        set_={"email": normalized_email},
    ).returning(LoginFailure)

    failure = db.scalar(
        statement,
        execution_options={"populate_existing": True},
    )

    if failure is None:
        raise RuntimeError("Failed to get or create LoginFailure record.")
    else: 
        return failure

def record_login_failure(failure: LoginFailure, now: datetime) -> None:
    retry_after = get_retry_after(failure, now)
    if retry_after > 0:
        raise LoginRateLimitError(retry_after)

    window_expired = now >= failure.window_started_at + timedelta(
        seconds=settings.LOGIN_FAILURE_WINDOW_SECONDS
    )
    block_expired = (
        failure.blocked_until is not None
        and now >= failure.blocked_until
    )
    if window_expired or block_expired:
        failure.failure_count = 0
        failure.window_started_at = now
        failure.blocked_until = None

    if failure.failure_count == 0:
        failure.window_started_at = now

    failure.failure_count += 1

    if failure.failure_count >= settings.LOGIN_FAILURE_LIMIT:
        failure.blocked_until = now + timedelta(
            seconds=settings.LOGIN_BLOCK_SECONDS
        )

def authenticate_user_with_rate_limit(db: Session, email: str, password: str) -> User:
    try:
        normalized_email = normalize_email(email)
        now = datetime.now(timezone.utc)
        failure = get_or_create_login_failure(db, normalized_email, now)
        now = datetime.now(timezone.utc)

        retry_after = get_retry_after(failure, now)
        if retry_after > 0:
            db.rollback()
            raise LoginRateLimitError(retry_after)

        try:
            user = authenticate_user(db, normalized_email, password)
        except InvalidCredentialsError:
            record_login_failure(failure, now)
            db.commit()
            raise

        db.delete(failure)
        db.commit()
        return user
    except SQLAlchemyError:
        db.rollback()
        raise
