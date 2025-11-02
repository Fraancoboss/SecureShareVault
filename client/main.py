from flask import Flask, request, jsonify, render_template
import base64
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from Crypto.Random import get_random_bytes

# Obtener el directorio raíz del proyecto
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, project_root)

from server.aes_utils import aes_encrypt
from server.shamir_core import split_secret
from server.config import (
    THRESHOLD,
    SERVER_HOST,
    SERVER_PORT,
    N_SHARES,
    AES_KEY_SIZE,
)
from client.config import SHARE_CUSTODIANS, SECURE_SHARE_STORAGE_DIR
from client.share_vault import SecureShareVault

app = Flask(__name__, template_folder=str(Path(__file__).parent / "templates"))

storage_dir = Path(project_root) / "server" / "message_store"
storage_dir.mkdir(parents=True, exist_ok=True)
store_path = storage_dir / "messages.jsonl"


def persist_envelope(data, share_refs):
    message_id = uuid.uuid4().hex
    envelope = {
        "message_id": message_id,
        "received_at": datetime.now(timezone.utc).isoformat(),
        "data": data,
        "share_references": share_refs,
        "threshold": THRESHOLD,
    }

    with store_path.open("a", encoding="utf-8") as handler:
        handler.write(json.dumps(envelope, ensure_ascii=True) + "\n")

    print(f"[{envelope['received_at']}] Mensaje cifrado almacenado con id={message_id}")
    print("   Referencias de custodios:", [ref.get("custodian") for ref in share_refs])

    return message_id


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/relay", methods=["POST"])
def relay():
    content = request.json or {}
    data = content.get("data", {})
    share_refs = content.get("share_references", [])

    if not isinstance(data, dict):
        return jsonify({"error": "Payload 'data' inválido."}), 400
    if not isinstance(share_refs, list):
        return jsonify({"error": "'share_references' debe ser una lista."}), 400

    required_fields = ("ciphertext", "nonce", "tag")
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Faltan campos requeridos en 'data'."}), 400

    try:
        base64.b64decode(data["ciphertext"], validate=True)
        base64.b64decode(data["nonce"], validate=True)
        base64.b64decode(data["tag"], validate=True)
    except Exception:
        return jsonify({"error": "Datos cifrados corruptos o no codificados en Base64."}), 400

    message_id = persist_envelope(data, share_refs)

    return jsonify({
        "message_id": message_id,
        "custodians_required": THRESHOLD,
        "note": "El servidor no conserva shares suficientes para reconstruir la clave.",
    })


@app.route("/api/ui/send", methods=["POST"])
def ui_send():
    payload = request.json or {}
    message = (payload.get("message") or "").strip()

    if not message:
        return jsonify({"error": "El mensaje no puede estar vacío."}), 400

    key = get_random_bytes(AES_KEY_SIZE)
    ciphertext, nonce, tag = aes_encrypt(message, key)

    shares = split_secret(int.from_bytes(key, "big"), n=N_SHARES, t=THRESHOLD)
    vault = SecureShareVault(SECURE_SHARE_STORAGE_DIR, SHARE_CUSTODIANS)
    share_refs = vault.distribute(shares)

    remaining = shares[len(SHARE_CUSTODIANS):]
    backup_path = None
    if remaining:
        backup_path = SECURE_SHARE_STORAGE_DIR / "ui_owner_backup.json"
        with backup_path.open("w", encoding="utf-8") as backup_file:
            json.dump(remaining, backup_file, separators=(",", ":"))

    data = {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "tag": base64.b64encode(tag).decode(),
    }

    message_id = persist_envelope(data, share_refs)

    reply_text = f"Copia desde servidor: {message}"
    reply_ciphertext, reply_nonce, reply_tag = aes_encrypt(reply_text, key)

    return jsonify({
        "message_id": message_id,
        "modified_message": reply_text,
        "ciphertext": data["ciphertext"],
        "nonce": data["nonce"],
        "tag": data["tag"],
        "share_references": [
            {"custodian": ref["custodian"], "share_id": ref["share_id"]}
            for ref in share_refs
        ],
        "backup_path": str(backup_path) if backup_path else None,
        "modified_ciphertext": base64.b64encode(reply_ciphertext).decode(),
        "modified_nonce": base64.b64encode(reply_nonce).decode(),
        "modified_tag": base64.b64encode(reply_tag).decode(),
    })


if __name__ == "__main__":
    print(f"Servidor en http://{SERVER_HOST}:{SERVER_PORT}")
    app.run(host=SERVER_HOST, port=SERVER_PORT)
