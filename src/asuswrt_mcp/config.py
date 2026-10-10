"""Runtime configuration loaded from environment variables."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from .errors import ConfigurationError
from .security import redact


class Settings(BaseSettings):
    """Server configuration.

    Values are intentionally optional where possible so the MCP server can start
    and expose capabilities even before a router is configured.
    """

    model_config = SettingsConfigDict(
        env_prefix="ASUSWRT_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    host: str | None = None
    username: str | None = None
    password: SecretStr | None = None
    http_port: int | None = Field(default=None, ge=1, le=65535)
    use_ssl: bool = False
    verify_tls: bool = False

    ssh_port: int = Field(default=22, ge=1, le=65535)
    ssh_username: str | None = None
    ssh_password: SecretStr | None = None
    ssh_key_file: Path | None = None
    prefer_ssh: bool = False

    allow_mutations: bool = False
    timeout_seconds: float = Field(default=10.0, gt=0)
    cache_seconds: float = Field(default=5.0, ge=0)

    @field_validator("host", "username", "ssh_username", mode="before")
    @classmethod
    def empty_string_to_none(cls, value: Any) -> Any:
        if value == "":
            return None
        return value

    @field_validator(
        "http_port",
        "password",
        "ssh_key_file",
        "ssh_password",
        mode="before",
    )
    @classmethod
    def blank_optional_to_none(cls, value: Any) -> Any:
        if value == "":
            return None
        return value

    @property
    def effective_ssh_username(self) -> str | None:
        return self.ssh_username or self.username

    @property
    def effective_ssh_password(self) -> str | None:
        secret = self.ssh_password or self.password
        return secret.get_secret_value() if secret else None

    @property
    def http_password(self) -> str:
        return self.password.get_secret_value() if self.password else ""

    def require_http(self) -> None:
        missing = [
            name
            for name, value in {
                "ASUSWRT_HOST": self.host,
                "ASUSWRT_USERNAME": self.username,
            }.items()
            if not value
        ]
        if missing:
            raise ConfigurationError(
                code="missing_http_config",
                message="Missing required HTTP router configuration.",
                details={"missing": missing},
            )

    def require_ssh(self) -> None:
        missing = [
            name
            for name, value in {
                "ASUSWRT_HOST": self.host,
                "ASUSWRT_USERNAME or ASUSWRT_SSH_USERNAME": self.effective_ssh_username,
            }.items()
            if not value
        ]
        if missing:
            raise ConfigurationError(
                code="missing_ssh_config",
                message="Missing required SSH router configuration.",
                details={"missing": missing},
            )

    def safe_dict(self) -> dict[str, Any]:
        data = self.model_dump(mode="json")
        data["ssh_username"] = self.effective_ssh_username
        for legacy_key in ("http_port", "use_ssl", "verify_tls", "prefer_ssh"):
            data.pop(legacy_key, None)
        data["connection_mode"] = "ssh-only"
        return redact(data)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


def reset_settings_cache() -> None:
    get_settings.cache_clear()
