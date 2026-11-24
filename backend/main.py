from datetime import datetime, timezone
from uuid import UUID

from fastapi import Depends, FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session

from database import get_db
from login_service import authenticate_user_with_rate_limit, LoginRateLimitError
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
    revoke_session
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

class InvalidSessionError(Exception):
    pass

class MeResponse(BaseModel):
    id: UUID
    email: str

app = FastAPI(title=settings.APP_NAME)


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
def register(payload: RegisterRequest, db: Session = Depends(get_db)):
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
def login(payload: LoginRequest, response: Response, db: Session = Depends(get_db)):
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
    token = create_session(db, user.id)

    response.set_cookie(
        key=settings.SESSION_COOKIE_NAME,
        value=token,
        max_age=settings.SESSION_ABSOLUTE_TIMEOUT_SECONDS,
        httponly=True,
        secure=settings.SESSION_COOKIE_SECURE,
        samesite="lax",
        path="/",
    )

    return LoginResponse(id=user.id, email=user.email)

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
    token = request.cookies.get(settings.SESSION_COOKIE_NAME)
    session = find_session_by_token(db, token) if token else None
    now = datetime.now(timezone.utc)

    if session is not None and is_session_valid(session, now):
        revoke_session(db, session, now)
    response.delete_cookie(
        key=settings.SESSION_COOKIE_NAME,
        path="/",
        secure=settings.SESSION_COOKIE_SECURE,
        httponly=True,
        samesite="lax",
    )
    response.status_code = 204
    return response