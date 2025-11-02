import json
from datetime import timedelta
from pathlib import Path

from flask_jwt_extended import create_access_token


def test_ui_send_endpoint_generates_modified_message(flask_env, auth_headers):
    client = flask_env.app.test_client()

    headers = {**auth_headers, "Content-Type": "application/json"}
    response = client.post("/api/ui/send", json={"message": "Hola mundo"}, headers=headers)
    assert response.status_code == 200

    payload = response.get_json()
    assert payload["modified_message"] == "Copia desde servidor: Hola mundo"
    assert payload["message_id"]
    assert len(payload["share_references"]) == len(flask_env.SHARE_CUSTODIANS[:flask_env.THRESHOLD])
    assert payload["processed_by"] == "tester"

    store_path = Path(flask_env.store_path)
    assert store_path.exists()

    saved = json.loads(store_path.read_text(encoding="utf-8").splitlines()[-1])
    assert saved["message_id"] == payload["message_id"]
    assert saved["data"]["ciphertext"] == payload["ciphertext"]

    for reference in payload["share_references"]:
        share_file = (
            flask_env.SECURE_SHARE_STORAGE_DIR
            / reference["custodian"]
            / f"{reference['share_id']}.json"
        )
        assert share_file.exists()


def test_relay_rejects_invalid_payload(flask_env, auth_headers):
    client = flask_env.app.test_client()

    response = client.post(
        "/api/relay",
        json={
            "data": {"ciphertext": "***", "nonce": "***", "tag": "***"},
            "share_references": [],
        },
        headers={**auth_headers, "Content-Type": "application/json"},
    )

    assert response.status_code == 400
    assert "error" in response.get_json()


def test_login_rejects_invalid_credentials(flask_env):
    client = flask_env.app.test_client()
    response = client.post(
        "/api/auth/login",
        json={"username": "tester", "password": "wrong"},
    )
    assert response.status_code == 401
    assert response.get_json()["error"] == "Credenciales inválidas."


def test_relay_requires_authorization(flask_env):
    client = flask_env.app.test_client()
    response = client.post("/api/relay", json={})
    assert response.status_code == 401


def test_expired_token_denied(flask_env):
    client = flask_env.app.test_client()
    with flask_env.app.app_context():
        expired_token = create_access_token(
            identity="tester",
            expires_delta=timedelta(seconds=-1),
        )

    response = client.post(
        "/api/ui/send",
        json={"message": "hola"},
        headers={"Authorization": f"Bearer {expired_token}", "Content-Type": "application/json"},
    )

    assert response.status_code in (401, 422)


def test_login_rate_limit_per_user(limited_flask_env):
    client = limited_flask_env.app.test_client()
    payload = {"username": "tester", "password": "wrong"}

    for _ in range(5):
        resp = client.post("/api/auth/login", json=payload)
        assert resp.status_code == 401

    limited_response = client.post("/api/auth/login", json=payload)
    assert limited_response.status_code == 429


def test_login_requires_captcha_header(captcha_flask_env):
    client = captcha_flask_env.app.test_client()

    no_captcha = client.post(
        "/api/auth/login",
        json={"username": "tester", "password": "secret"},
    )
    assert no_captcha.status_code == 403
    assert "error" in no_captcha.get_json()

    with_header = client.post(
        "/api/auth/login",
        headers={"X-Test-Captcha": "token123"},
        json={"username": "tester", "password": "secret"},
    )
    assert with_header.status_code == 200
