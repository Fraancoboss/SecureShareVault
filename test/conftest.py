import importlib
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def _build_flask_app(tmp_path, monkeypatch, extra_env=None):
    monkeypatch.setenv("USE_SSL", "false")
    monkeypatch.delenv("SSL_CERT_PATH", raising=False)
    monkeypatch.delenv("SSL_KEY_PATH", raising=False)
    monkeypatch.setenv("AUTH_USERNAME", "tester")
    monkeypatch.setenv("AUTH_PASSWORD", "secret")
    monkeypatch.setenv("JWT_SECRET_KEY", "test-secret-key")
    monkeypatch.setenv("JWT_EXPIRES_MINUTES", "5")
    monkeypatch.setenv("FRONTEND_ORIGIN", "http://127.0.0.1:5000")

    if extra_env:
        for key, value in extra_env.items():
            if value is None:
                monkeypatch.delenv(key, raising=False)
            else:
                monkeypatch.setenv(key, value)

    shares_dir = tmp_path / "shares"
    message_store_dir = tmp_path / "message_store"
    shares_dir.mkdir()
    message_store_dir.mkdir()

    import client.config as client_config

    monkeypatch.setattr(client_config, "SECURE_SHARE_STORAGE_DIR", shares_dir)

    flask_main = importlib.reload(importlib.import_module("client.main"))
    flask_main.SECURE_SHARE_STORAGE_DIR = shares_dir
    flask_main.storage_dir = message_store_dir
    flask_main.store_path = message_store_dir / "messages.jsonl"
    flask_main.USE_SSL = False

    return flask_main


@pytest.fixture
def flask_env(tmp_path, monkeypatch):
    """Prepara entorno aislado para pruebas del servidor Flask sin rate limiting."""
    extra_env = {
        "LIMITER_ENABLED": "false",
        "REQUIRE_CAPTCHA": "false",
    }
    return _build_flask_app(tmp_path, monkeypatch, extra_env)


@pytest.fixture
def limited_flask_env(tmp_path, monkeypatch):
    """Flask app con rate limiting habilitado y umbrales bajos para pruebas."""
    extra_env = {
        "LIMITER_ENABLED": "true",
        "LIMITER_DEFAULT_RATE": "100 per minute",
        "REQUIRE_CAPTCHA": "false",
    }
    return _build_flask_app(tmp_path, monkeypatch, extra_env)


@pytest.fixture
def captcha_flask_env(tmp_path, monkeypatch):
    """Flask app con requisito de captcha en login."""
    extra_env = {
        "LIMITER_ENABLED": "false",
        "REQUIRE_CAPTCHA": "true",
        "CAPTCHA_HEADER": "X-Test-Captcha",
    }
    return _build_flask_app(tmp_path, monkeypatch, extra_env)


@pytest.fixture
def auth_headers(flask_env):
    client = flask_env.app.test_client()
    response = client.post(
        "/api/auth/login",
        json={"username": "tester", "password": "secret"},
    )
    assert response.status_code == 200
    token = response.get_json()["access_token"]
    return {"Authorization": f"Bearer {token}"}
