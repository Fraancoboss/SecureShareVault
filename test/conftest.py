import importlib
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


@pytest.fixture
def flask_env(tmp_path, monkeypatch):
    """Prepara entorno aislado para pruebas del servidor Flask."""
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

    return flask_main
