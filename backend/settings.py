from pydantic_settings import BaseSettings
from typing import Literal


class Settings(BaseSettings):
    APP_ENV: Literal["development", "test"] = "development"
    APP_NAME: str = "Health Management App"


settings = Settings()