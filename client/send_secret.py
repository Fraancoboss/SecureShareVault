import os
import sys
import json
import base64
from pathlib import Path
from urllib.parse import urljoin

import requests
from Crypto.Random import get_random_bytes

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from server.aes_utils import aes_encrypt
from server.shamir_core import split_secret
from server.config import N_SHARES, THRESHOLD
from client.config import (
    SERVER_URL,
    SHARE_CUSTODIANS,
    SECURE_SHARE_STORAGE_DIR,
)
from client.share_vault import SecureShareVault

AUTH_USERNAME = os.getenv("AUTH_USERNAME", "admin")
AUTH_PASSWORD = os.getenv("AUTH_PASSWORD", "changeme")

api_base = SERVER_URL.rsplit("/", 1)[0] + "/"
login_url = urljoin(api_base, "auth/login")

login_response = requests.post(
    login_url,
    json={"username": AUTH_USERNAME, "password": AUTH_PASSWORD},
    timeout=10,
)

if login_response.status_code != 200:
    raise SystemExit(f"❌ Error autenticando usuario: {login_response.text}")

token = login_response.json()["access_token"]
headers = {"Authorization": f"Bearer {token}"}

# Flujo principal
secret_text = input("Introduce tu texto secreto: ")
key = get_random_bytes(32)

# Cifrar
ciphertext, nonce, tag = aes_encrypt(secret_text, key)

# Preparar datos
data = {
    "ciphertext": base64.b64encode(ciphertext).decode(),
    "nonce": base64.b64encode(nonce).decode(),
    "tag": base64.b64encode(tag).decode(),
}

# Generar shares del secreto (sin exponerlos al servidor)
shares = split_secret(int.from_bytes(key, "big"), n=N_SHARES, t=THRESHOLD)
vault = SecureShareVault(SECURE_SHARE_STORAGE_DIR, SHARE_CUSTODIANS)
share_references = vault.distribute(shares)

print(f"🔐 Generados {N_SHARES} shares (umbral: {THRESHOLD}).")
print("   Los custodios asignados conservan los shares necesarios para reconstruir la clave.")

# Guardar shares sobrantes como respaldo del propietario
remaining = shares[len(SHARE_CUSTODIANS):]
if remaining:
    owner_backup_path = Path(SECURE_SHARE_STORAGE_DIR).resolve() / "owner_backup.json"
    with owner_backup_path.open("w", encoding="utf-8") as backup_file:
        json.dump(remaining, backup_file)
    print(f"   Copia de seguridad local en: {owner_backup_path}")

# Enviar solo metadatos al servidor
payload = {
    "data": data,
    "share_references": [
        {"custodian": ref["custodian"], "share_id": ref["share_id"]}
        for ref in share_references
    ],
}

response = requests.post(SERVER_URL, json=payload, headers=headers, timeout=15)

if response.status_code == 200:
    reply = response.json()
    print("✅ Servidor confirmó recepción cifrada:")
    print(f"   message_id: {reply.get('message_id')}")
    print(f"   custodios_requeridos: {reply.get('custodians_required')}")
else:
    print("❌ Error en la entrega:", response.text)
