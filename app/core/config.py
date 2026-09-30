from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Ticketdesk API"
    app_version: str = "0.1.0"
    environment: str = "development"
    database_url: str = "sqlite:///./ticketdesk.db"
    attachment_root: str = "./var/attachments"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
