"""
Configuración centralizada del sistema de cifrado
"""

# Configuración del servidor
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5000

# Configuración Shamir Secret Sharing
N_SHARES = 5      # Total de shares a generar
THRESHOLD = 3     # Mínimo necesario para reconstruir

# Configuración AES
AES_KEY_SIZE = 32  # 256 bits para AES
NONCE_SIZE = 16    # Tamaño standard para GCM