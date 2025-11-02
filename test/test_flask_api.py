import json
from pathlib import Path


def test_ui_send_endpoint_generates_modified_message(flask_env):
    client = flask_env.app.test_client()

    response = client.post("/api/ui/send", json={"message": "Hola mundo"})
    assert response.status_code == 200

    payload = response.get_json()
    assert payload["modified_message"] == "Copia desde servidor: Hola mundo"
    assert payload["message_id"]
    assert len(payload["share_references"]) == len(flask_env.SHARE_CUSTODIANS[:flask_env.THRESHOLD])

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


def test_relay_rejects_invalid_payload(flask_env):
    client = flask_env.app.test_client()

    response = client.post(
        "/api/relay",
        json={
            "data": {"ciphertext": "***", "nonce": "***", "tag": "***"},
            "share_references": [],
        },
    )

    assert response.status_code == 400
    assert "error" in response.get_json()
