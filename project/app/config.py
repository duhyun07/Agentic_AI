from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

PLACEHOLDER_CREDENTIAL_FIELDS = ("clova_api_key", "github_token", "nvd_api_key")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql+psycopg://postgres:postgres@localhost:5432/kernel_dashboard"
    clova_api_key: str = "changeme"
    clova_request_id: str = "changeme"
    clova_base_url: str = "https://clovastudio.stream.ntruss.com"
    github_token: str = "changeme"
    nvd_api_key: str = "changeme"
    embedding_dim: int = 1024

    syzbot_poll_interval_minutes: int = Field(default=15, ge=1)
    cve_poll_interval_hours: int = Field(default=24, ge=1)
    github_poc_poll_interval_hours: int = Field(default=24, ge=1)

    github_rate_limit_per_minute: int = Field(default=10, ge=1)
    nvd_min_seconds_between_calls: float = Field(default=0.6, ge=0)
    hcx_max_retries: int = Field(default=3, ge=1)

    @field_validator(*PLACEHOLDER_CREDENTIAL_FIELDS)
    @classmethod
    def _reject_placeholder_credential(cls, v: str, info) -> str:
        if v.strip().lower() == "changeme":
            raise ValueError(
                f"{info.field_name} is still set to the placeholder value 'changeme'; "
                "set a real credential via .env or the environment"
            )
        return v


@lru_cache
def get_settings() -> Settings:
    return Settings()
