import pytest

from app.config import DEFAULT_DEVELOPMENT_SECRET, Settings


def test_production_rejects_default_secret(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("SECRET_KEY", DEFAULT_DEVELOPMENT_SECRET)
    monkeypatch.setenv("SUPABASE_URL", "https://example.supabase.co")
    monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "service-key")

    with pytest.raises(RuntimeError, match="development SECRET_KEY"):
        Settings.from_env()


def test_production_rejects_debug(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("SECRET_KEY", "production-secret")
    monkeypatch.setenv("DEBUG", "true")
    monkeypatch.setenv("SUPABASE_URL", "https://example.supabase.co")
    monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "service-key")

    with pytest.raises(RuntimeError, match="DEBUG must be false"):
        Settings.from_env()