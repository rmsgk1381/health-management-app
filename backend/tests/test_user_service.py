from unittest.mock import Mock
from sqlalchemy.orm import Session
from sqlalchemy import create_engine, select
from database import database_url
from user_service import register_user, DuplicateEmailError, authenticate_user, InvalidCredentialsError
from models import User
import pytest
import user_service


# 회원가입 사용자가 정규화한 이메일로 DB에 저장되는지 확인한다.
def test_register_user_saves_normalized_email(postgres_db):
    user = register_user(postgres_db, "  Step16.New@EXAMPLE.COM  ", "demo-password")
    assert user.id is not None
    saved_email = postgres_db.scalar(select(User.email).where(User.id == user.id))
    assert saved_email == "step16.new@example.com"

# 사전 검사를 건너뛴 DB 중복 오류를 롤백하고 기존 사용자를 다시 조회할 수 있는지 확인한다.
def test_register_user_rolls_back_on_database_duplicate(postgres_db, monkeypatch):
    email = "step16.duplicate@example.com"
    existing_user = register_user(postgres_db, email, "demo-password")
    existing_id = existing_user.id

    with monkeypatch.context() as patch:
        patch.setattr(postgres_db, "scalar", lambda _statement: None)

        with pytest.raises(DuplicateEmailError):
            register_user(postgres_db, email, "demo-password")
    saved_id = postgres_db.scalar(select(User.id).where(User.email == email))
    assert saved_id == existing_id

# 이미 존재하는 이메일은 사용자 추가나 커밋 전에 거부하는지 확인한다.
def test_register_user_rejects_existing_email():
    db = Mock(spec=Session)
    db.scalar.return_value = User(email="test.user@example.com")
    with pytest.raises(DuplicateEmailError):
        register_user(db, "test.user@example.com", "demo-password")
    
    db.add.assert_not_called()
    db.commit.assert_not_called()

# 로그인 이메일을 정규화하고 올바른 비밀번호로 등록 사용자를 인증하는지 확인한다.
def test_authenticate_user_accepts_valid_credentials(postgres_db):
    registered_user = register_user(postgres_db, "step19.auth@example.com", "demo-password")
    authenticated_user = authenticate_user(postgres_db, "  Step19.Auth@EXAMPLE.COM  ", "demo-password")
    assert authenticated_user.id == registered_user.id

# 등록된 사용자의 비밀번호가 틀리면 인증을 거부하는지 확인한다.
def test_authenticate_user_rejects_wrong_password(postgres_db):
    email = "step19.wrong@example.com"
    register_user(postgres_db, email, "demo-password")
    with pytest.raises(InvalidCredentialsError):
        authenticate_user(postgres_db, email, "wrong-password")

# 미등록 사용자는 더미 해시 검증을 수행하고 검증 결과와 관계없이 인증을 거부하는지 확인한다.
def test_authenticate_user_rejects_unknown_user(monkeypatch):
    db = Mock(spec=Session)
    db.scalar.return_value = None

    verify = Mock(return_value=True)
    monkeypatch.setattr(user_service, "verify_password", verify)
    with pytest.raises(InvalidCredentialsError):
        authenticate_user(db, "step19.missing@example.com", "demo-password")
    verify.assert_called_once_with(
        "demo-password", user_service._DUMMY_PASSWORD_HASH
    )
