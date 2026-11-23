from fastapi.testclient import TestClient
from main import app
from database import get_db
from settings import settings
from user_service import register_user

from sqlalchemy import select
from models import LoginFailure, Session as AuthSession
from security import hash_session_token
from http.cookies import SimpleCookie

client = TestClient(app)


# 헬스 체크 API가 200과 정상 상태를 반환하는지 확인한다.
def test_health_returns_ok():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

# 등록되지 않은 경로가 404를 반환하는지 확인한다.
def test_unknown_path_returns_404():
    response = client.get("/not-found")
    assert response.status_code == 404
    assert response.json() == {"detail": "Not Found"}

# 회원가입 이메일 누락을 422로 거부하고 비밀번호를 응답에 노출하지 않는지 확인한다.
def test_register_returns_422_when_email_is_missing():
    password = "step17-dummy-only"
    response = client.post(
        "/api/v1/auth/register",
        json={"password": password},
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"
    assert password not in response.text

# 회원가입 성공 시 201과 사용자 ID 및 정규화한 이메일만 반환하는지 확인한다.
def test_register_returns_201(postgres_db, monkeypatch):
    monkeypatch.setitem(app.dependency_overrides, get_db, lambda: postgres_db)
    response = client.post(
        "/api/v1/auth/register",
        json={"email": "Step17.New@EXAMPLE.COM", "password": "step17-dummy-only"},
    )
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == "step17.new@example.com"
    assert set(data) == {"id", "email"}

# 대소문자가 다른 중복 이메일의 회원가입을 409로 거부하는지 확인한다.
def test_register_returns_409_for_duplicate_email(postgres_db, monkeypatch):
    monkeypatch.setitem(app.dependency_overrides, get_db, lambda: postgres_db)
    response1 = client.post(
        "/api/v1/auth/register",
        json={"email": "Step17.Conflict@EXAMPLE.COM", "password": "step17-dummy-only"},
    )
    assert response1.status_code == 201

    response2 = client.post(
        "/api/v1/auth/register",
        json={"email": "step17.conflict@example.com", "password": "step17-dummy-only"},
    )
    assert response2.status_code == 409
    assert response2.json()["error"]["code"] == "DUPLICATE_EMAIL"
    

# 빈 비밀번호로 회원가입을 요청하면 422를 반환하는지 확인한다.
def test_register_returns_422_when_password_is_empty(postgres_db, monkeypatch):
    monkeypatch.setitem(app.dependency_overrides, get_db, lambda: postgres_db)
    response = client.post(
        "/api/v1/auth/register",
        json={"email": "step17.empty@example.com", "password": ""},
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"

# 로그인 성공 시 사용자 정보, DB 세션 연결 및 쿠키 속성이 올바른지 확인한다.
def test_login_returns_200_and_sets_session_cookie(postgres_db, monkeypatch):
    monkeypatch.setitem(app.dependency_overrides, get_db, lambda: postgres_db)
    user = register_user(postgres_db, "step19.login@example.com", "testpassword")
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "step19.login@example.com", "password": "testpassword"},
    )
    assert response.status_code == 200
    assert response.json() == {"id": str(user.id), "email": user.email}
    token = response.cookies.get(settings.SESSION_COOKIE_NAME)
    assert token is not None

    saved_session = postgres_db.scalar(
        select(AuthSession).where(
            AuthSession.session_token_hash == hash_session_token(token)
        )
    )
    assert saved_session is not None
    assert saved_session.user_id == user.id
    cookies = SimpleCookie()
    cookies.load(response.headers["set-cookie"])
    cookie = cookies[settings.SESSION_COOKIE_NAME]

    assert cookie["httponly"] is True
    assert cookie["samesite"] == "lax"
    assert cookie["path"] == "/"
    assert cookie["max-age"] == str(settings.SESSION_ABSOLUTE_TIMEOUT_SECONDS)
    assert bool(cookie["secure"]) == settings.SESSION_COOKIE_SECURE
    assert cookie["domain"] == ""

# 잘못된 비밀번호를 401로 거부하고 세션과 쿠키를 발급하지 않는지 확인한다.
def test_login_returns_401_when_password_is_wrong(postgres_db, monkeypatch):
    monkeypatch.setitem(app.dependency_overrides, get_db, lambda: postgres_db)
    user = register_user(postgres_db, "step19.login@example.com", "testpassword")
    response = client.post(
            "/api/v1/auth/login",
            json={"email": "step19.login@example.com", "password": "wrong-password"},
        )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "INVALID_CREDENTIALS"
    assert response.cookies.get(settings.SESSION_COOKIE_NAME) is None
    saved_session = postgres_db.scalar(
        select(AuthSession).where(AuthSession.user_id == user.id)
    )
    assert saved_session is None

# 미등록 사용자의 로그인을 공통 401 오류로 거부하고 쿠키를 발급하지 않는지 확인한다.
def test_login_returns_401_when_user_does_not_exist(postgres_db, monkeypatch):
    monkeypatch.setitem(app.dependency_overrides, get_db, lambda: postgres_db)
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "step19.login@example.com", "password": "testpassword"},
    )
    assert response.status_code == 401
    assert response.json() == {
        "error": {
            "code": "INVALID_CREDENTIALS",
            "message": "이메일 또는 비밀번호가 올바르지 않습니다.",
            "details": [],
        }
    }
    assert response.cookies.get(settings.SESSION_COOKIE_NAME) is None

# 로그인 이메일 누락 시 422 응답, 비밀번호 비노출 및 쿠키 미발급을 확인한다.
def test_login_returns_422_when_email_is_missing(postgres_db, monkeypatch):
    monkeypatch.setitem(app.dependency_overrides, get_db, lambda: postgres_db)
    password = "step19-dummy-only"
    response = client.post(
                "/api/v1/auth/login",
                json={"password": password},
            )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"
    assert password not in response.text
    assert response.cookies.get(settings.SESSION_COOKIE_NAME) is None

# 빈 로그인 비밀번호를 422로 거부하고 쿠키와 실패 기록을 생성하지 않는다.
def test_login_returns_422_when_password_is_empty(postgres_db, monkeypatch):
    monkeypatch.setitem(app.dependency_overrides, get_db, lambda: postgres_db)
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "step19.login@example.com", "password": ""},
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"
    assert response.cookies.get(settings.SESSION_COOKIE_NAME) is None

    saved_failure = postgres_db.scalar(
        select(LoginFailure).where(
            LoginFailure.email == "step19.login@example.com"
        )
    )
    assert saved_failure is None

# 5회 로그인 실패 후 추가 요청을 429로 거부하고 세션과 쿠키를 발급하지 않는다.
def test_login_returns_429_when_failure_limit_is_reached(postgres_db, monkeypatch):
    monkeypatch.setitem(app.dependency_overrides, get_db, lambda: postgres_db)
    monkeypatch.setattr(settings, "LOGIN_FAILURE_LIMIT", 5)
    monkeypatch.setattr(settings, "LOGIN_BLOCK_SECONDS", 60)

    email = "step19.api-limit@example.com"
    user = register_user(postgres_db, email, "testpassword")

    for _ in range(5):
        response = client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": "wrong-password"},
        )
        assert response.status_code == 401

    response = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "testpassword"},
    )

    assert response.status_code == 429
    assert response.json()["error"]["code"] == "LOGIN_RATE_LIMITED"
    retry_after = int(response.headers["Retry-After"])
    assert 1 <= retry_after <= 60

    assert response.cookies.get(settings.SESSION_COOKIE_NAME) is None

    saved_session = postgres_db.scalar(
        select(AuthSession).where(AuthSession.user_id == user.id)
    )
    assert saved_session is None

# 미등록 이메일도 대소문자와 관계없이 같은 실패 기록으로 집계한다.
def test_login_limits_normalized_email_for_unknown_user(postgres_db, monkeypatch):
    monkeypatch.setitem(app.dependency_overrides, get_db, lambda: postgres_db)
    monkeypatch.setattr(settings, "LOGIN_FAILURE_LIMIT", 2)
    monkeypatch.setattr(settings, "LOGIN_BLOCK_SECONDS", 60)

    email = "step19.unknown-limit@example.com"

    for input_email in [email.upper(), email]:
        response = client.post(
            "/api/v1/auth/login",
            json={"email": input_email, "password": "wrong-password"},
        )
        assert response.status_code == 401

    response = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "wrong-password"},
    )
    assert response.status_code == 429

    saved_failure = postgres_db.scalar(
        select(LoginFailure).where(LoginFailure.email == email)
    )
    assert saved_failure is not None
    assert saved_failure.failure_count == 2