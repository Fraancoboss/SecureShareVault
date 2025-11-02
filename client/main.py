from flask import Flask, request, jsonify, render_template
import base64
import json
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from Crypto.Random import get_random_bytes
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    get_jwt_identity,
    jwt_required,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

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

app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "change-this-in-prod")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(
    minutes=int(os.getenv("JWT_EXPIRES_MINUTES", "15"))
)
jwt = JWTManager(app)

frontend_origin = os.getenv("FRONTEND_ORIGIN", "http://127.0.0.1:5000")
CORS(
    app,
    resources={"/api/*": {"origins": frontend_origin}},
    supports_credentials=False,
    expose_headers=["Content-Type"],
    allow_headers=["Content-Type", "Authorization"],
)

limiter_enabled = os.getenv("LIMITER_ENABLED", "true").lower() in {"1", "true", "yes"}
limiter_rate = os.getenv("LIMITER_DEFAULT_RATE", "60 per minute")
if limiter_enabled:
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=[limiter_rate],
        storage_uri="memory://",
    )
else:
    limiter = Limiter(get_remote_address, app=app, enabled=False)


def rate_limit_per_user():
    payload = request.get_json(silent=True) or {}
    username = (payload.get("username") or "").strip().lower()
    if username:
        return f"user:{username}"
    return f"ip:{get_remote_address()}"


@app.errorhandler(429)
def handle_rate_limit(exc):
    return jsonify({"error": "Límite de solicitudes excedido. Intenta nuevamente más tarde."}), 429

storage_dir = Path(project_root) / "server" / "message_store"
storage_dir.mkdir(parents=True, exist_ok=True)
store_path = storage_dir / "messages.jsonl"

USE_SSL = os.getenv("USE_SSL", "false").lower() in {"1", "true", "yes"}
SSL_CERT_PATH = Path(os.getenv("SSL_CERT_PATH", str(Path(project_root) / "cert.pem"))).expanduser()
SSL_KEY_PATH = Path(os.getenv("SSL_KEY_PATH", str(Path(project_root) / "key.pem"))).expanduser()

AUTH_USERNAME = os.getenv("AUTH_USERNAME", "admin")
AUTH_PASSWORD = os.getenv("AUTH_PASSWORD", "changeme")
CAPTCHA_REQUIRED = os.getenv("REQUIRE_CAPTCHA", "false").lower() in {"1", "true", "yes"}
CAPTCHA_HEADER = os.getenv("CAPTCHA_HEADER", "X-Captcha-Token")


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


@app.route("/api/auth/login", methods=["POST"])
@limiter.limit("10 per minute")
@limiter.limit("5 per minute", key_func=rate_limit_per_user)
def login():
    payload = request.json or {}
    username = (payload.get("username") or "").strip()
    password = payload.get("password") or ""

    if CAPTCHA_REQUIRED and not request.headers.get(CAPTCHA_HEADER):
        return jsonify({"error": "Validación adicional requerida."}), 403

    if not username or not password:
        return jsonify({"error": "Credenciales inválidas."}), 401

    if username != AUTH_USERNAME or password != AUTH_PASSWORD:
        return jsonify({"error": "Credenciales inválidas."}), 401

    token = create_access_token(identity=username)
    expires_minutes = int(app.config["JWT_ACCESS_TOKEN_EXPIRES"].total_seconds() // 60)
    return jsonify({"access_token": token, "expires_in_minutes": expires_minutes})


@app.route("/api/relay", methods=["POST"])
@jwt_required()
@limiter.limit("30 per minute")
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
        "processed_by": get_jwt_identity(),
    })


@app.route("/api/ui/send", methods=["POST"])
@jwt_required()
@limiter.limit("15 per minute")
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
        "processed_by": get_jwt_identity(),
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
    ssl_context = None
    protocol = "http"

    if USE_SSL:
        if not SSL_CERT_PATH.exists() or not SSL_KEY_PATH.exists():
            raise FileNotFoundError(
                f"No se encontraron los certificados TLS en {SSL_CERT_PATH} y {SSL_KEY_PATH}."
            )
        ssl_context = (str(SSL_CERT_PATH), str(SSL_KEY_PATH))
        protocol = "https"

    print(f"Servidor en {protocol}://{SERVER_HOST}:{SERVER_PORT}")
    app.run(host=SERVER_HOST, port=SERVER_PORT, ssl_context=ssl_context)
