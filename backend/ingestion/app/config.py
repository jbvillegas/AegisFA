import os
from dataclasses import dataclass

DEFAULT_DEVELOPMENT_SECRET = "dev-only-change-me"


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    return int(os.getenv(name, str(default)))


def _env_float(name: str, default: float) -> float:
    return float(os.getenv(name, str(default)))


@dataclass(frozen=True)
class Settings:
    environment: str
    secret_key: str
    debug: bool
    port: int
    supabase_url: str
    supabase_service_role_key: str
    openai_api_key: str | None
    upload_bucket: str
    model_bucket: str
    max_content_length: int
    max_upload_part_bytes: int
    max_upload_session_assembly_bytes: int
    upload_session_ttl_seconds: int
    max_upload_sessions: int
    queue_backend: str
    worker_count: int
    worker_timeout_seconds: int

    @classmethod
    def from_env(cls) -> "Settings":
        environment = (
            os.getenv("APP_ENV", os.getenv("FLASK_ENV", "development")).strip().lower()
        )
        secret_key = os.getenv("SECRET_KEY", "")
        if not secret_key:
            if environment == "development":
                secret_key = DEFAULT_DEVELOPMENT_SECRET
            else:
                raise RuntimeError("SECRET_KEY must be set outside development.")
        if secret_key == DEFAULT_DEVELOPMENT_SECRET and environment != "development":
            raise RuntimeError(
                "The development SECRET_KEY cannot be used outside development."
            )

        supabase_url = os.getenv("SUPABASE_URL", "").strip()
        supabase_service_role_key = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()
        if not supabase_url or not supabase_service_role_key:
            raise RuntimeError(
                "SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set."
            )

        debug = _env_bool("DEBUG", environment == "development")
        if environment != "development" and debug:
            raise RuntimeError("DEBUG must be false outside development.")

        return cls(
            environment=environment,
            secret_key=secret_key,
            debug=debug,
            port=_env_int("PORT", 5001),
            supabase_url=supabase_url,
            supabase_service_role_key=supabase_service_role_key,
            openai_api_key=os.getenv("OPENAI_API_KEY") or None,
            upload_bucket=os.getenv("SUPABASE_BUCKET_NAME", "log-files"),
            model_bucket=os.getenv("SUPABASE_MODEL_BUCKET_NAME", "ml-models"),
            max_content_length=_env_int("MAX_CONTENT_LENGTH", 120 * 1024 * 1024),
            max_upload_part_bytes=_env_int("MAX_UPLOAD_PART_BYTES", 16 * 1024 * 1024),
            max_upload_session_assembly_bytes=_env_int(
                "MAX_UPLOAD_SESSION_ASSEMBLY_BYTES", 2 * 1024 * 1024 * 1024
            ),
            upload_session_ttl_seconds=_env_int("UPLOAD_SESSION_TTL_SECONDS", 3600),
            max_upload_sessions=_env_int("MAX_UPLOAD_SESSIONS", 100),
            queue_backend=os.getenv("QUEUE_BACKEND", "inline"),
            worker_count=_env_int("WORKER_COUNT", 1),
            worker_timeout_seconds=_env_int("WORKER_TIMEOUT_SECONDS", 120),
        )
