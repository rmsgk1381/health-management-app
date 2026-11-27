import hashlib
import secrets

from pwdlib import PasswordHash

from settings import settings

_password_hasher = PasswordHash.recommended()

def normalize_email(email: str) -> str:
    cleaned = email.strip()
    return cleaned.lower()

def hash_password(password: str) -> str:
    return _password_hasher.hash(password)

def verify_password(password: str, stored_hash: str) -> bool:
    return _password_hasher.verify(password, stored_hash)

def generate_session_token() -> str:
    return secrets.token_urlsafe(32)

def hash_session_token(token: str) -> str:
    return hashlib.sha256(token.encode('utf-8')).hexdigest()

def is_allowed_origin(origin: str | None) -> bool:
    return origin == settings.FRONTEND_ORIGIN
