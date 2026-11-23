from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from sqlalchemy import select
from models import User
from security import normalize_email, hash_password, verify_password
from psycopg.errors import UniqueViolation

_DUMMY_PASSWORD_HASH = hash_password("step19-dummy-only")

def register_user(db: Session, email: str, password: str) -> User:
    normalized_email = normalize_email(email)
    existing_user = db.scalar(select(User).where(User.email == normalized_email))
    if existing_user is not None:
        raise DuplicateEmailError("이미 등록된 이메일입니다.")
    user = User(email=normalized_email, password_hash=hash_password(password))
    db.add(user)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        original_error = exc.orig
        if (isinstance(original_error, UniqueViolation) and original_error.diag.constraint_name == "users_email_key"):
            raise DuplicateEmailError("이미 등록된 이메일입니다.")
        raise
    db.refresh(user)
    return user

def authenticate_user(db: Session, email: str, password: str) -> User:
    normalized_email = normalize_email(email)
    user = db.scalar(select(User).where(User.email == normalized_email))
    if user is not None:
        stored_hash = user.password_hash
    else:
        stored_hash = _DUMMY_PASSWORD_HASH

    password_valid = verify_password(password, stored_hash)
    if user is None or not password_valid:
        raise InvalidCredentialsError("이메일 또는 비밀번호가 올바르지 않습니다.")
    return user

class DuplicateEmailError(Exception):
    pass

class InvalidCredentialsError(Exception):
    pass