import os
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    # App Settings
    APP_NAME: str = "LLM Prompt Injection Firewall"
    ENV: str = "development"
    DEBUG: bool = True
    HOST: str = "127.0.0.1"
    PORT: int = 8000

    # Database Settings
    DATABASE_URL: str = "sqlite:///./firewall.db"

    # Firewall Settings
    FIREWALL_MODE: str = "learning"  # learning, sanitize, enforce
    THRESHOLD_ALLOW: int = 25
    THRESHOLD_WARN: int = 50
    THRESHOLD_SANITIZE: int = 75

    # Authentication & Security
    JWT_SECRET: str = "super-secret-firewall-jwt-key-change-in-production"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    RATE_LIMIT_PER_MINUTE: int = 60

    # Downstream LLM API Settings
    DOWNSTREAM_LLM_URL: Optional[str] = ""
    DOWNSTREAM_LLM_API_KEY: Optional[str] = ""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

# Instantiate settings singleton
settings = Settings()
