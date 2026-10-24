"""Settings read from environment variables (and an optional .env file). No third-party settings library."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

LLM_BACKENDS = ("anthropic", "heuristic")
EMBEDDERS = ("auto", "fastembed", "hashing")
EFFORTS = ("low", "medium", "high", "xhigh", "max")  # "default" omits the field and lets the API choose


class ConfigError(ValueError):
    """An environment variable has an unusable value."""


def load_env_file(path: str | Path = ".env") -> None:
    """Read KEY=VALUE lines into ``os.environ`` without overriding variables that are already set."""
    p = Path(path)
    if not p.is_file():
        return
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip().strip("\"'")
        if key and key not in os.environ:
            os.environ[key] = value


def _int(env: Mapping[str, str], name: str, default: int, minimum: int = 1) -> int:
    raw = env.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be a whole number, got {raw!r}") from exc
    if value < minimum:
        raise ConfigError(f"{name} must be at least {minimum}, got {value}")
    return value


@dataclass(frozen=True)
class Settings:
    llm_backend: str = "anthropic"
    anthropic_api_key: str | None = None
    model: str = "claude-sonnet-5-5"
    effort: str | None = "medium"
    embedder: str = "auto"
    db_path: str = "./data/audits.sqlite3"
    max_upload_mb: int = 10
    max_pages: int = 200
    concurrency: int = 4
    top_k: int = 6
    api_key: str | None = None
    cors_origins: tuple[str, ...] = ()
    static_dir: str | None = None

    @property
    def max_upload_bytes(self) -> int:
        return self.max_upload_mb * 1024 * 1024

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Settings:
        env = os.environ if env is None else env
        backend = env.get("HIPAA_AUDIT_LLM_BACKEND", "anthropic").strip().lower()
        if backend not in LLM_BACKENDS:
            raise ConfigError(f"HIPAA_AUDIT_LLM_BACKEND must be one of {LLM_BACKENDS}, got {backend!r}")
        embedder = env.get("HIPAA_AUDIT_EMBEDDER", "auto").strip().lower()
        if embedder not in EMBEDDERS:
            raise ConfigError(f"HIPAA_AUDIT_EMBEDDER must be one of {EMBEDDERS}, got {embedder!r}")
        effort: str | None = env.get("HIPAA_AUDIT_EFFORT", "medium").strip().lower()
        if effort in ("", "default", "none"):
            effort = None
        elif effort not in EFFORTS:
            raise ConfigError(f"HIPAA_AUDIT_EFFORT must be one of {EFFORTS} or 'default', got {effort!r}")
        origins = tuple(o.strip() for o in env.get("HIPAA_AUDIT_CORS_ORIGINS", "").split(",") if o.strip())
        return cls(
            llm_backend=backend,
            anthropic_api_key=env.get("ANTHROPIC_API_KEY") or None,
            model=env.get("HIPAA_AUDIT_MODEL") or "claude-sonnet-5-5",
            effort=effort,
            embedder=embedder,
            db_path=env.get("HIPAA_AUDIT_DB_PATH") or "./data/audits.sqlite3",
            max_upload_mb=_int(env, "HIPAA_AUDIT_MAX_UPLOAD_MB", 10),
            max_pages=_int(env, "HIPAA_AUDIT_MAX_PAGES", 200),
            concurrency=_int(env, "HIPAA_AUDIT_CONCURRENCY", 4),
            top_k=_int(env, "HIPAA_AUDIT_TOP_K", 6),
            api_key=env.get("HIPAA_AUDIT_API_KEY") or None,
            cors_origins=origins,
            static_dir=env.get("HIPAA_AUDIT_STATIC_DIR") or None,
        )
