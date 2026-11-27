from datetime import datetime, timezone, timedelta

from fastapi.testclient import TestClient
import pytest

from main import app
from database import get_db
from settings import settings
from user_service import register_user
from session_service import create_session, find_session_by_token

from sqlalchemy import select
from models import LoginFailure, Session as AuthSession
from security import hash_session_token
from http.cookies import SimpleCookie

client = TestClient(app, headers={"Origin": settings.FRONTEND_ORIGIN})

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

# 로그인 성공 시 사용자 정보, 세션 쿠키와 CSRF 토큰을 발급하고 해시를 저장하는지 확인한다.
def test_login_returns_200_and_sets_session_cookie(postgres_db, monkeypatch):
    monkeypatch.setitem(app.dependency_overrides, get_db, lambda: postgres_db)
    user = register_user(postgres_db, "step19.login@example.com", "testpassword")

    old_token = create_session(postgres_db, user.id)
    old_session = postgres_db.scalar(
        select(AuthSession).where(
            AuthSession.session_token_hash == hash_session_token(old_token)
        )
    )
    assert old_session is not None
    old_session.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    postgres_db.commit()

    stale_failure_email = "step-supplement.stale@example.com"
    postgres_db.add(
        LoginFailure(
            email=stale_failure_email,
            failure_count=1,
            window_started_at=datetime.now(timezone.utc)
            - timedelta(seconds=settings.LOGIN_FAILURE_WINDOW_SECONDS + 1),
            blocked_until=None,
        )
    )
    postgres_db.commit()

    response = client.post(
        "/api/v1/auth/login",
        json={"email": "step19.login@example.com", "password": "testpassword"},
    )
    assert response.status_code == 200
    csrf_token = response.json()["csrf_token"]

    assert postgres_db.scalar(
        select(LoginFailure).where(
            LoginFailure.email == stale_failure_email
        )
    ) is None


    assert postgres_db.scalar(
        select(AuthSession).where(
            AuthSession.session_token_hash == hash_session_token(old_token)
        )
    ) is None

    assert response.json() == {
        "id": str(user.id),
        "email": user.email,
        "csrf_token": csrf_token,
    }
    token = response.cookies.get(settings.SESSION_COOKIE_NAME)
    assert token is not None

    saved_session = postgres_db.scalar(
        select(AuthSession).where(
            AuthSession.session_token_hash == hash_session_token(token)
        )
    )
    assert saved_session is not None
    assert saved_session.csrf_token_hash == hash_session_token(csrf_token)
    assert saved_session.csrf_token_hash != csrf_token
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
    assert response.headers.get("Cache-Control") == "no-store"
    assert response.cookies.get(settings.CSRF_COOKIE_NAME) == csrf_token

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

# 유효한 세션 쿠키로 내 정보 경로에서 인증된 사용자 정보를 반환하는지 확인한다.
def test_get_me_returns_authenticated_user(postgres_db, monkeypatch):
    monkeypatch.setitem(app.dependency_overrides, get_db, lambda: postgres_db)
    user = register_user(
        postgres_db, "step20.me@example.com", "testpassword"
    )
    token = create_session(postgres_db, user.id)

    session = postgres_db.scalar(
        select(AuthSession).where(
            AuthSession.session_token_hash == hash_session_token(token)
        )
    )
    assert session is not None

    last_seen_before = datetime.now(timezone.utc) - timedelta(days=1)
    session.last_seen_at = last_seen_before
    postgres_db.commit()

    with TestClient(app) as test_client:
        test_client.cookies.set(settings.SESSION_COOKIE_NAME, token)
        response = test_client.get("/api/v1/users/me")

    assert response.status_code == 200
    assert response.json() == {"id": str(user.id), "email": user.email}

    postgres_db.refresh(session)
    assert session.last_seen_at > last_seen_before

@pytest.mark.parametrize("token", [None, "unknown-dummy-session-token"])
# 쿠키가 없거나 DB에 없는 세션 토큰이면 내 정보 요청을 공통 401로 거부한다.
def test_get_me_rejects_missing_or_unknown_session_token(
    token, postgres_db, monkeypatch
):
    monkeypatch.setitem(app.dependency_overrides, get_db, lambda: postgres_db)

    with TestClient(app) as test_client:
        if token is not None:
            test_client.cookies.set(settings.SESSION_COOKIE_NAME, token)
        response = test_client.get("/api/v1/users/me")

    assert response.status_code == 401
    assert response.json() == {
        "error": {
            "code": "INVALID_SESSION",
            "message": "인증이 필요합니다.",
            "details": [],
        }
    }

# 절대·유휴 만료 또는 폐기된 세션은 내 정보 요청에서 공통 401로 거부한다.
@pytest.mark.parametrize("expired_state", ["absolute", "idle", "revoked"])
def test_get_me_rejects_expired_or_revoked_session(
    expired_state, postgres_db, monkeypatch
):
    monkeypatch.setitem(app.dependency_overrides, get_db, lambda: postgres_db)
    user = register_user(
        postgres_db, f"step20.{expired_state}@example.com", "testpassword"
    )
    token = create_session(postgres_db, user.id)
    session = postgres_db.scalar(
        select(AuthSession).where(
            AuthSession.session_token_hash == hash_session_token(token)
        )
    )
    assert session is not None

    now = datetime.now(timezone.utc)
    if expired_state == "absolute":
        session.expires_at = now - timedelta(minutes=1)
    elif expired_state == "idle":
        session.last_seen_at = now - timedelta(days=8)
    else:
        session.revoked_at = now - timedelta(minutes=1)
    postgres_db.commit()

    with TestClient(app) as test_client:
        test_client.cookies.set(settings.SESSION_COOKIE_NAME, token)
        response = test_client.get("/api/v1/users/me")

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "INVALID_SESSION"

@pytest.mark.parametrize("session_state", ["active", "missing", "unknown", "expired"])
# 로그아웃이 세션 상태와 무관하게 쿠키를 지우고 반복 요청을 안전하게 처리하는지 확인한다.
def test_logout_is_idempotent_and_clears_cookie(
    session_state, postgres_db, monkeypatch
):
    monkeypatch.setitem(app.dependency_overrides, get_db, lambda: postgres_db)
    token = None
    session = None
    csrf_token = "step21-logout-csrf-token"

    if session_state in {"active", "expired"}:
        user = register_user(
            postgres_db, f"step21.{session_state}@example.com", "testpassword"
        )
        token = create_session(
            postgres_db, user.id, csrf_token=csrf_token
        )
        session = postgres_db.scalar(
            select(AuthSession).where(
                AuthSession.session_token_hash == hash_session_token(token)
            )
        )
        assert session is not None

        if session_state == "expired":
            session.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
            postgres_db.commit()
    elif session_state == "unknown":
        token = "unknown-dummy-session-token"

    with TestClient(
        app,
        headers={"Origin": settings.FRONTEND_ORIGIN},
    ) as test_client:
        if token is not None:
            test_client.cookies.set(
                settings.SESSION_COOKIE_NAME,
                token,
                domain="testserver.local",
                path="/",
            )
        if session_state == "active":
            test_client.cookies.set(
                settings.CSRF_COOKIE_NAME,
                csrf_token,
                domain="testserver.local",
                path="/",
            )

        response = test_client.post(
            "/api/v1/auth/logout",
            headers=(
                {"X-CSRF-Token": csrf_token}
                if session_state == "active"
                else {}
            ),
        )
        cookie = SimpleCookie()
        cookie.load(response.headers["set-cookie"])

        assert response.status_code == 204
        assert cookie[settings.SESSION_COOKIE_NAME].value == ""
        assert cookie[settings.SESSION_COOKIE_NAME]["max-age"] == "0"
        assert cookie[settings.SESSION_COOKIE_NAME]["expires"]
        assert cookie[settings.SESSION_COOKIE_NAME]["path"] == "/"
        assert test_client.cookies.get(settings.SESSION_COOKIE_NAME) is None
        if session_state == "active":
            assert cookie[settings.CSRF_COOKIE_NAME].value == ""
            assert test_client.cookies.get(settings.CSRF_COOKIE_NAME) is None

        if session is not None:
            postgres_db.refresh(session)
            if session_state == "active":
                assert session.revoked_at is not None
            else:
                assert session.revoked_at is None

        repeated_response = test_client.post("/api/v1/auth/logout")
        if session_state == "active" and token is not None:
            test_client.cookies.set(
                settings.SESSION_COOKIE_NAME,
                token,
                domain="testserver.local",
                path="/",
            )
            protected_response = test_client.get("/api/v1/users/me")
            assert protected_response.status_code == 401

    assert repeated_response.status_code == 204

@pytest.mark.parametrize("origin", [None, "http://127.0.0.1:5174"])
# Origin이 없거나 허용되지 않은 로그아웃 요청을 거부하는지 확인한다.
def test_logout_rejects_missing_or_untrusted_origin(
    origin, postgres_db, monkeypatch
):
    monkeypatch.setitem(app.dependency_overrides, get_db, lambda: postgres_db)
    headers = {"Origin": origin} if origin is not None else {}

    with TestClient(app) as test_client:
        response = test_client.post(
            "/api/v1/auth/logout",
            headers=headers,
        )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "CSRF_VALIDATION_FAILED"

@pytest.mark.parametrize("csrf_cookie_state", ["matching", "mismatch", "missing"])
# 쿠키 토큰이 활성 세션의 해시와 일치할 때만 기존 토큰을 반환하는지 확인한다.
def test_get_csrf_returns_token_only_when_cookie_matches_session(
    csrf_cookie_state, postgres_db, monkeypatch
):
    monkeypatch.setitem(app.dependency_overrides, get_db, lambda: postgres_db)
    user = register_user(postgres_db, "step23.csrf@example.com", "testpassword")
    csrf_token = "step23-csrf-test-token"
    session_token = create_session(
        postgres_db, user.id, csrf_token=csrf_token
    )

    with TestClient(app) as test_client:
        test_client.cookies.set(settings.SESSION_COOKIE_NAME, session_token)

        if csrf_cookie_state == "matching":
            test_client.cookies.set(settings.CSRF_COOKIE_NAME, csrf_token)
        elif csrf_cookie_state == "mismatch":
            test_client.cookies.set(
                settings.CSRF_COOKIE_NAME, "different-csrf-token"
            )

        response = test_client.get("/api/v1/auth/csrf")

    if csrf_cookie_state == "matching":
        assert response.status_code == 200
    else:
        assert response.status_code == 204
    if response.status_code == 200:
        assert response.json()["csrf_token"] == csrf_token

    assert response.headers["Cache-Control"] == "no-store"

@pytest.mark.parametrize("origin", [None, "http://127.0.0.1:5174"])
# Origin이 없거나 허용 목록과 다르면 회원가입을 거부하는지 확인한다.
def test_register_rejects_missing_or_untrusted_origin(
    origin, postgres_db, monkeypatch
):
    monkeypatch.setitem(app.dependency_overrides, get_db, lambda: postgres_db)
    headers = {"Origin": origin} if origin is not None else {}

    with TestClient(app) as test_client:
        response = test_client.post(
            "/api/v1/auth/register",
            json={
                "email": "step23.origin@example.com",
                "password": "testpassword",
            },
            headers=headers,
        )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "CSRF_VALIDATION_FAILED"

@pytest.mark.parametrize("origin", [None, "http://127.0.0.1:5174"])
# Origin이 없거나 허용되지 않으면 로그인 처리를 시작하기 전에 거부하는지 확인한다.
def test_login_rejects_missing_or_untrusted_origin(
    origin, postgres_db, monkeypatch
):
    monkeypatch.setitem(app.dependency_overrides, get_db, lambda: postgres_db)
    headers = {"Origin": origin} if origin is not None else {}

    with TestClient(app) as test_client:
        response = test_client.post(
            "/api/v1/auth/login",
            json={
                "email": "step23.origin-login@example.com",
                "password": "dummy-password",
            },
            headers=headers,
        )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "CSRF_VALIDATION_FAILED"

@pytest.mark.parametrize("csrf_header", [None, "wrong-csrf-token"])
# 활성 세션의 로그아웃에서 CSRF 헤더가 없거나 틀리면 폐기하지 않는지 확인한다.
def test_logout_rejects_missing_or_invalid_csrf_token(
    csrf_header, postgres_db, monkeypatch
):
    monkeypatch.setitem(app.dependency_overrides, get_db, lambda: postgres_db)
    user = register_user(
        postgres_db, "step23.logout-csrf@example.com", "testpassword"
    )
    csrf_token = "step23-logout-csrf-token"
    session_token = create_session(
        postgres_db, user.id, csrf_token=csrf_token
    )
    session = find_session_by_token(postgres_db, session_token)
    assert session is not None

    headers = {"X-CSRF-Token": csrf_header} if csrf_header is not None else {}

    with TestClient(
        app,
        headers={"Origin": settings.FRONTEND_ORIGIN},
    ) as test_client:
        test_client.cookies.set(
            settings.SESSION_COOKIE_NAME,
            session_token,
            domain="testserver.local",
            path="/",
        )
        response = test_client.post(
            "/api/v1/auth/logout",
            headers=headers,
        )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "CSRF_VALIDATION_FAILED"

    postgres_db.refresh(session)
    assert session.revoked_at is None

# 활성 세션에서 CSRF 갱신 요청이 새 토큰과 쿠키를 발급하고 해시를 교체하는지 확인한다.
def test_post_csrf_refresh_rotates_token_for_active_session(
    postgres_db, monkeypatch
):
    monkeypatch.setitem(app.dependency_overrides, get_db, lambda: postgres_db)
    user = register_user(
        postgres_db, "step23.csrf-refresh@example.com", "testpassword"
    )
    old_csrf_token = "step23-old-refresh-token"
    session_token = create_session(
        postgres_db, user.id, csrf_token=old_csrf_token
    )
    session = find_session_by_token(postgres_db, session_token)
    assert session is not None

    with TestClient(
        app,
        headers={"Origin": settings.FRONTEND_ORIGIN},
    ) as test_client:
        test_client.cookies.set(settings.SESSION_COOKIE_NAME, session_token)
        response = test_client.post("/api/v1/auth/csrf")

    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    new_csrf_token = response.json()["csrf_token"]
    assert new_csrf_token != old_csrf_token
    assert response.cookies.get(settings.CSRF_COOKIE_NAME) == new_csrf_token
    postgres_db.refresh(session)
    assert session.csrf_token_hash == hash_session_token(new_csrf_token)
    assert session.csrf_token_hash != new_csrf_token

@pytest.mark.parametrize(
    ("origin", "session_state", "expected_status"),
    [
        (None, "active", 403),
        ("http://127.0.0.1:5174", "active", 403),
        (settings.FRONTEND_ORIGIN, "missing", 401),
    ],
)
# Origin 또는 활성 세션이 없는 CSRF 갱신 요청을 거부하는지 확인한다.
def test_post_csrf_refresh_rejects_invalid_origin_or_missing_session(
    origin, session_state, expected_status, postgres_db, monkeypatch
):
    monkeypatch.setitem(app.dependency_overrides, get_db, lambda: postgres_db)
    session_token = None
    csrf_token = "step23-refresh-rejection-token"

    if session_state == "active":
        user = register_user(
            postgres_db, "step23.refresh-rejection@example.com", "testpassword"
        )
        session_token = create_session(
            postgres_db, user.id, csrf_token=csrf_token
        )

    headers = {"Origin": origin} if origin is not None else {}
    with TestClient(app) as test_client:
        if session_token is not None:
            test_client.cookies.set(settings.SESSION_COOKIE_NAME, session_token)

        response = test_client.post(
            "/api/v1/auth/csrf",
            headers=headers,
        )

    assert response.status_code == expected_status
    expected_error_code = (
        "CSRF_VALIDATION_FAILED"
        if expected_status == 403
        else "INVALID_SESSION"
    )
    assert response.json()["error"]["code"] == expected_error_code
    if session_state == "active":
        expected_csrf_hash = hash_session_token(csrf_token)

        assert session_token is not None
        session = find_session_by_token(postgres_db, session_token)

        assert session is not None
        postgres_db.refresh(session)
        assert session.csrf_token_hash == expected_csrf_hash
