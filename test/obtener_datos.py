import json
import base64
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from server.shamir_core import recover_secret
from server.aes_utils import aes_decrypt
from server.config import THRESHOLD
from client.config import SHARE_CUSTODIANS, SECURE_SHARE_STORAGE_DIR


def load_latest_share_files():
    """Localiza el último share generado para cada custodio necesario."""
    base_dir = Path(SECURE_SHARE_STORAGE_DIR).expanduser().resolve()
    if not base_dir.exists():
        raise FileNotFoundError(
            f"No se encontró el directorio de shares en {base_dir}. "
            "Ejecuta el cliente para generarlos."
        )

    shares = []
    for custodian in SHARE_CUSTODIANS[:THRESHOLD]:
        custodian_dir = base_dir / custodian
        if not custodian_dir.exists():
            raise FileNotFoundError(
                f"No hay shares almacenados para el custodio '{custodian}' en {custodian_dir}."
            )

        share_files = sorted(custodian_dir.glob("*.json"))
        if not share_files:
            raise FileNotFoundError(
                f"No se encontraron archivos .json con shares en {custodian_dir}."
            )

        latest_file = share_files[-1]
        data = json.loads(latest_file.read_text(encoding="utf-8"))
        shares.append((data["x"], data["y"]))

    return shares


def load_latest_envelope():
    """Recupera el último mensaje cifrado almacenado en el servidor."""
    store_file = (PROJECT_ROOT / "server" / "message_store" / "messages.jsonl").resolve()
    if not store_file.exists():
        raise FileNotFoundError(
            f"No se encontró el archivo de mensajes en {store_file}. "
            "Asegúrate de que el servidor haya recibido datos."
        )

    lines = store_file.read_text(encoding="utf-8").splitlines()
    if not lines:
        raise RuntimeError("El archivo de mensajes está vacío.")

    return json.loads(lines[-1])


def main():
    shares = load_latest_share_files()
    key_int = recover_secret(shares, THRESHOLD)
    key = key_int.to_bytes(32, "big")

    envelope = load_latest_envelope()
    encrypted = envelope["data"]

    plaintext = aes_decrypt(
        base64.b64decode(encrypted["ciphertext"]),
        key,
        base64.b64decode(encrypted["nonce"]),
        base64.b64decode(encrypted["tag"]),
    )
    print("Mensaje descifrado:", plaintext.decode("utf-8"))


if __name__ == "__main__":
    main()
