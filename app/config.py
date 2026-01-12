# app/config.py
from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Typed, cached application settings from environment variables."""

    # ── Core App ────────────────────────────────────────────────────────────────
    ENVIRONMENT: Literal["development", "staging", "production"] = "development"
    DEBUG: bool = False

    # ── API ─────────────────────────────────────────────────────────────────────
    API_V1_PREFIX: str = "/api/v1"
    PROJECT_NAME: str = "Verify Kenya"
    PROJECT_DESCRIPTION: str = "Secure QR-based product verification & payments in Kenya"

    # ── Database ────────────────────────────────────────────────────────────────
    DATABASE_URL: str = Field(
        default="postgresql+asyncpg://user:password@localhost/verify_kenya",
        description="PostgreSQL async connection string"
    )
    SQLALCHEMY_ECHO: bool = False

    # ── Security ────────────────────────────────────────────────────────────────
    JWT_SECRET: SecretStr = Field(
        ...,
        description="HS256 secret — min 32 characters. REQUIRED."
    )
    JWT_ALGORITHM: Literal["HS256"] = "HS256"
    JWT_EXPIRATION_HOURS: int = 24

    MASTER_ENCRYPTION_KEY: SecretStr = Field(
        ...,
        description="32-byte (256-bit) key for AES-256-GCM, base64 or hex encoded. REQUIRED."
    )

    # ── Paystack (Kenya payments) ──────────────────────────────────────────────
    PAYSTACK_SECRET_KEY: SecretStr = Field(
        ...,
        description="Paystack secret key (sk_... or test_sk_...)"
    )
    PAYSTACK_PUBLIC_KEY: str = Field(
        default="",
        description="Paystack public key (pk_...)"
    )
    PAYSTACK_WEBHOOK_SECRET: SecretStr | None = None  # optional, but recommended

    # ── Model configuration ─────────────────────────────────────────────────────
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",           # ignore unknown env vars
        env_nested_delimiter="__", # optional: support nested like DB__POOL_SIZE
    )

    @field_validator("JWT_SECRET")
    @classmethod
    def validate_jwt_secret_length(cls, v: SecretStr) -> SecretStr:
        if len(v.get_secret_value()) < 32:
            raise ValueError("JWT_SECRET must be at least 32 characters long")
        return v

    @field_validator("MASTER_ENCRYPTION_KEY")
    @classmethod
    def validate_encryption_key(cls, v: SecretStr) -> SecretStr:
        key_str = v.get_secret_value()
        # You could add base64/hex decode check here if you want strict format
        if len(key_str) not in (32, 44):  # rough check: raw 32 bytes or base64
            raise ValueError("MASTER_ENCRYPTION_KEY should be 32 bytes (or base64 equivalent)")
        return v


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Cached singleton access to settings."""
    return Settings()