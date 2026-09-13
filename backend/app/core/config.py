"""
Central configuration for the platform.
Values are read from environment variables (see .env.example).
"""
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    APP_NAME: str = "Automated Security Assessment Platform"
    ENV: str = "development"

    # Database
    DATABASE_URL: str = "sqlite:///./security_assessment.db"

    # JWT auth
    SECRET_KEY: str = "CHANGE_ME_IN_PRODUCTION_use_a_random_64_char_string"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # Scanning
    REQUEST_TIMEOUT_SECONDS: int = 10
    MAX_CONCURRENT_SCANS: int = 5

    class Config:
        env_file = ".env"


settings = Settings()
