from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Aegis"
    app_version: str = "0.1.0"

    aegis_fingerprint_key: str = Field(
        min_length=32,
    )

    nvidia_api_key: str
    nvidia_base_url: str = "https://integrate.api.nvidia.com/v1"
    nvidia_model: str = "openai/gpt-oss-120b"

    ai_request_timeout_seconds: float = Field(
        default=45.0,
        ge=5.0,
        le=600.0,
    )
    ai_max_retries: int = Field(
        default=0,
        ge=0,
        le=3,
    )

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
