from pathlib import Path
from typing import Literal
from pydantic import PositiveInt

from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):

    model_config = SettingsConfigDict(
        env_file = Path(__file__).parent / ".env",
        env_file_encoding = "utf-8"
    )

    APP_ENV: Literal["development", "test"] = "development"
    APP_NAME: str = "Health Management App"

    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_USER: str
    POSTGRES_PASSWORD: str
    POSTGRES_DB: str

    SESSION_ABSOLUTE_TIMEOUT_SECONDS: PositiveInt = 30 * 24 * 60 * 60
    SESSION_COOKIE_NAME: str = "hma_session"
    SESSION_COOKIE_SECURE: bool = False

    LOGIN_FAILURE_WINDOW_SECONDS: PositiveInt = 15 * 60
    LOGIN_FAILURE_LIMIT: PositiveInt = 5
    LOGIN_BLOCK_SECONDS: PositiveInt = 60

    SESSION_IDLE_TIMEOUT_SECONDS: PositiveInt = 7 * 24 * 60 * 60

settings = Settings()  # pyright: ignore[reportCallIssue]