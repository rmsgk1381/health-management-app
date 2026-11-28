from datetime import datetime, timezone
from uuid import UUID

from fastapi import Depends, FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session

from database import get_db
from login_service import (
    authenticate_user_with_rate_limit,
    delete_expired_login_failures,
    LoginRateLimitError,
)
from security import (
    generate_session_token,
    hash_session_token,
    is_allowed_origin,
)
from settings import settings
from user_service import (
    register_user,
    DuplicateEmailError,
    InvalidCredentialsError,
)
from session_service import (
    AuthSession,
    create_session,
    find_session_by_token,
    is_session_valid,
    update_session_activity,
    revoke_session,
    delete_invalid_sessions,
    update_session_csrf_token,
)

class HealthResponse(BaseModel):
    status: str


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1)

class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1)

class RegisterResponse(BaseModel):
    id: UUID
    email: str

class LoginResponse(BaseModel):
    id: UUID
    email: str
    csrf_token: str

class InvalidSessionError(Exception):
    pass

class CsrfValidationError(Exception):
    pass

class MeResponse(BaseModel):
    id: UUID
    email: str

app = FastAPI(title=settings.APP_NAME)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.FRONTEND_ORIGIN],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-CSRF-Token"],
)

@app.exception_handler(RequestValidationError)
async def handle_validation_error(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content={
            "error": {
                "code": "VALIDATION_ERROR",
                "message": "입력값이 유효하지 않습니다.",
                "details": [],
            }
        },
    )

@app.exception_handler(InvalidSessionError)
async def handle_invalid_session(request: Request, exc: InvalidSessionError):
    return JSONResponse(
        status_code=401,
        content={
            "error": {
                "code": "INVALID_SESSION",
                "message": "인증이 필요합니다.",
                "details": [],
            }
        },
    )

@app.exception_handler(CsrfValidationError)
async def handle_csrf_validation_error(
    request: Request,
    exc: CsrfValidationError,
):
    return JSONResponse(
        status_code=403,
        content={
            "error": {
                "code": "CSRF_VALIDATION_FAILED",
                "message": "요청 출처 또는 CSRF 토큰이 유효하지 않습니다.",
                "details": [],
            }
        },
    )

def require_allowed_origin(request: Request) -> None:
    origin = request.headers.get("origin")
    if not is_allowed_origin(origin):
        raise CsrfValidationError()

def require_authenticated_session(
    request: Request,
    db: Session = Depends(get_db),
) -> AuthSession:
    token = request.cookies.get(settings.SESSION_COOKIE_NAME)
    session = find_session_by_token(db, token) if token else None
    now = datetime.now(timezone.utc)

    if session is None or not is_session_valid(session, now):
        raise InvalidSessionError()

    update_session_activity(db, session, now)
    return session


@app.get("/health", response_model=HealthResponse)
async def health():
    return HealthResponse(status="ok")


@app.post(
    "/api/v1/auth/register",
    response_model=RegisterResponse,
    status_code=201,
)
def register(
    request: Request,
    payload: RegisterRequest,
    db: Session = Depends(get_db),
):
    require_allowed_origin(request)
    try:
        user = register_user(db, str(payload.email), payload.password)
    except DuplicateEmailError:
        return JSONResponse(
            status_code=409,
            content={
                "error": {
                    "code": "DUPLICATE_EMAIL",
                    "message": "이미 등록된 이메일입니다.",
                    "details": [],
                }
            },
        )
    return RegisterResponse(id=user.id, email=user.email)

@app.post(
    "/api/v1/auth/login",
    response_model=LoginResponse,
    status_code=200,
)
def login(
    request: Request,
    payload: LoginRequest,
    response: Response,
    db: Session = Depends(get_db),
):
    require_allowed_origin(request)
    try:
        user = authenticate_user_with_rate_limit(
            db, str(payload.email), payload.password
        )
    except InvalidCredentialsError:
        return JSONResponse(
            status_code=401,
            content={
                "error": {
                    "code": "INVALID_CREDENTIALS",
                    "message": "이메일 또는 비밀번호가 올바르지 않습니다.",
                    "details": [],
                }
            },
        )
    except LoginRateLimitError as exc:
        return JSONResponse(
            status_code=429,
            headers={"Retry-After": str(exc.retry_after)},
            content={
                "error": {
                    "code": "LOGIN_RATE_LIMITED",
                    "message": "로그인 시도 횟수를 초과했습니다.",
                    "details": [],
                }
            },
        )
    delete_expired_login_failures(db, datetime.now(timezone.utc))
    delete_invalid_sessions(db, user.id, datetime.now(timezone.utc))
    csrf_token = generate_session_token()
    token = create_session(db, user.id, csrf_token=csrf_token)

    response.set_cookie(
        key=settings.CSRF_COOKIE_NAME,
        value=csrf_token,
        max_age=settings.SESSION_ABSOLUTE_TIMEOUT_SECONDS,
        httponly=True,
        secure=settings.SESSION_COOKIE_SECURE,
        samesite="lax",
        path="/",
    )

    response.set_cookie(
        key=settings.SESSION_COOKIE_NAME,
        value=token,
        max_age=settings.SESSION_ABSOLUTE_TIMEOUT_SECONDS,
        httponly=True,
        secure=settings.SESSION_COOKIE_SECURE,
        samesite="lax",
        path="/",
    )
    response.headers["Cache-Control"] = "no-store"

    return LoginResponse(
        id=user.id,
        email=user.email,
        csrf_token=csrf_token,
    )

@app.get("/api/v1/auth/csrf")
def get_csrf_token(
    request: Request,
    db: Session = Depends(get_db),
) -> Response:
    session_token = request.cookies.get(settings.SESSION_COOKIE_NAME)
    csrf_token = request.cookies.get(settings.CSRF_COOKIE_NAME)
    session = find_session_by_token(db, session_token) if session_token else None
    now = datetime.now(timezone.utc)

    if session is None or not is_session_valid(session, now):
        return Response(
            status_code=204,
            headers={"Cache-Control": "no-store"},
        )

    if (
        csrf_token is None
        or session.csrf_token_hash is None
        or hash_session_token(csrf_token) != session.csrf_token_hash
    ):
        return Response(
            status_code=204,
            headers={"Cache-Control": "no-store"},
        )

    return JSONResponse(
        content={"csrf_token": csrf_token},
        headers={"Cache-Control": "no-store"},
    )

@app.post("/api/v1/auth/csrf")
def refresh_csrf_token(
    request: Request,
    db: Session = Depends(get_db),
) -> Response:
    require_allowed_origin(request)

    session_token = request.cookies.get(settings.SESSION_COOKIE_NAME)
    session = find_session_by_token(db, session_token) if session_token else None
    now = datetime.now(timezone.utc)

    if session is None or not is_session_valid(session, now):
        raise InvalidSessionError()

    update_session_activity(db, session, now)

    csrf_token = generate_session_token()
    update_session_csrf_token(db, session, csrf_token)

    response = JSONResponse(
        content={"csrf_token": csrf_token},
        headers={"Cache-Control": "no-store"},
    )
    response.set_cookie(
        key=settings.CSRF_COOKIE_NAME,
        value=csrf_token,
        max_age=settings.SESSION_ABSOLUTE_TIMEOUT_SECONDS,
        httponly=True,
        secure=settings.SESSION_COOKIE_SECURE,
        samesite="lax",
        path="/",
    )
    return response

@app.get("/api/v1/users/me", response_model=MeResponse)
def get_me(
    session: AuthSession = Depends(require_authenticated_session),
) -> MeResponse:
    return MeResponse(id=session.user.id, email=session.user.email)

@app.post("/api/v1/auth/logout", status_code=204)
def logout(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> Response:
    require_allowed_origin(request)
    token = request.cookies.get(settings.SESSION_COOKIE_NAME)
    session = find_session_by_token(db, token) if token else None
    now = datetime.now(timezone.utc)

    if session is not None and is_session_valid(session, now):
        csrf_token = request.headers.get("x-csrf-token")
        if (
            csrf_token is None
            or session.csrf_token_hash is None
            or hash_session_token(csrf_token) != session.csrf_token_hash
        ):
            raise CsrfValidationError()
        revoke_session(db, session, now)
    response.delete_cookie(
        key=settings.SESSION_COOKIE_NAME,
        path="/",
        secure=settings.SESSION_COOKIE_SECURE,
        httponly=True,
        samesite="lax",
    )
    response.delete_cookie(
        key=settings.CSRF_COOKIE_NAME,
        path="/",
        secure=settings.SESSION_COOKIE_SECURE,
        httponly=True,
        samesite="lax",
    )
    response.status_code = 204
    return response
