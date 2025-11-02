from Crypto.Random import get_random_bytes
from server.aes_utils import aes_encrypt, aes_decrypt
from server.shamir_core import split_secret, recover_secret


def test_end_to_end():
    message = "Mensaje ultrasecreto"
    key = get_random_bytes(32)

    ciphertext, nonce, tag = aes_encrypt(message, key)

    shares = split_secret(int.from_bytes(key, "big"), n=5, t=3)

    recovered_key = recover_secret(shares[:3], 3).to_bytes(32, "big")

    decrypted = aes_decrypt(ciphertext, recovered_key, nonce, tag).decode()

    assert decrypted == message, "El mensaje desencriptado no coincide con el original"
