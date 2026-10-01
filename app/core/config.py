from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict

# Safe local-development default. A "*" entry is not an escape hatch: Settings.cors_origins
# drops it (see FORBIDDEN_CORS_ORIGINS), so configuring one disables CORS instead of
# allowing every origin (CWE-942).
DEFAULT_CORS_ALLOWED_ORIGINS = "http://localhost:3000,http://127.0.0.1:3000"

# Origin values that must never be handed to CORSMiddleware:
#   "*"    - starlette treats any allow_origins list containing "*" as allow-all and emits
#            "Access-Control-Allow-Origin: *" on every response, which is CWE-942 again.
#   "null" - the opaque origin sent by sandboxed iframes, file:// pages and some redirects;
#            allow-listing it hands CORS to pages nobody controls.
FORBIDDEN_CORS_ORIGINS = frozenset({"*", "null"})


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
    def cors_configured_entries(self) -> list[str]:
        """Every non-empty entry as written in configuration, including forbidden ones."""
        return [entry.strip() for entry in self.cors_allowed_origins.split(",") if entry.strip()]

    @property
    def cors_origins(self) -> list[str]:
        """Configured CORS origins as an allow-list.

        Forbidden entries are dropped rather than raised on, so a misconfigured deployment
        fails closed (fewer or no cross-origin grants) instead of failing open or refusing
        to start.
        """
        return [
            origin
            for origin in self.cors_configured_entries
            if origin.lower() not in FORBIDDEN_CORS_ORIGINS
        ]

    @property
    def cors_allow_credentials(self) -> bool:
        """Credentials are only ever allowed for a concrete, non-wildcard allow-list."""
        origins = self.cors_origins
        # A dropped entry means the configuration cannot be taken at face value, so the
        # surviving origins are served without credentials rather than guessing the intent.
        return bool(origins) and origins == self.cors_configured_entries


@lru_cache
def get_settings() -> Settings:
    return Settings()
