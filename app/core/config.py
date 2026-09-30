from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict

# Safe local-development default. Never use "*" here: a wildcard origin combined
# with credentialed requests lets any site read authenticated responses (CWE-942).
DEFAULT_CORS_ALLOWED_ORIGINS = "http://localhost:3000,http://127.0.0.1:3000"


class Settings(BaseSettings):
    app_name: str = "Ticketdesk API"
    app_version: str = "0.1.0"
    environment: str = "development"
    database_url: str = "sqlite:///./ticketdesk.db"
    attachment_root: str = "./var/attachments"
    # Comma-separated allow-list, overridable via the CORS_ALLOWED_ORIGINS env var.
    cors_allowed_origins: str = DEFAULT_CORS_ALLOWED_ORIGINS

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    @property
    def cors_origins(self) -> list[str]:
        """Configured CORS origins as an allow-list."""
        return [origin.strip() for origin in self.cors_allowed_origins.split(",") if origin.strip()]

    @property
    def cors_allow_credentials(self) -> bool:
        """Credentials are only ever allowed for a concrete, non-wildcard allow-list."""
        origins = self.cors_origins
        return bool(origins) and "*" not in origins


@lru_cache
def get_settings() -> Settings:
    return Settings()
