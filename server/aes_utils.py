from Crypto.Cipher import AES

def aes_encrypt(message, key: bytes):
    """Cifra un mensaje con AES-GCM. Admite tanto str como bytes."""
    cipher = AES.new(key, AES.MODE_GCM)

    # Aseguramos que message sea bytes
    if isinstance(message, str):
        message = message.encode('utf-8')

    ciphertext, tag = cipher.encrypt_and_digest(message)
    return ciphertext, cipher.nonce, tag

def aes_decrypt(ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes):  # ← ORDEN CORREGIDO
    """Descifra un mensaje con AES-GCM."""
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext


