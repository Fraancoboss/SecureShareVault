# Configuración del cliente
from pathlib import Path

SERVER_URL = "http://127.0.0.1:5000/api/relay"

# Distribución de shares: custodios lógicos y directorio de almacenamiento
SHARE_CUSTODIANS = ["custodio_alpha", "custodio_bravo", "custodio_charlie"]
SECURE_SHARE_STORAGE_DIR = Path(__file__).resolve().parents[1] / "client_secure_shares"
