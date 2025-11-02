import pytest
from Crypto.Random import get_random_bytes

from server import shamir_core
from server.aes_utils import aes_encrypt, aes_decrypt
from server.shamir_core import split_secret, recover_secret


def test_aes_encrypt_decrypt_roundtrip():
    key = get_random_bytes(32)
    plaintext = "hola criptografía"

    ciphertext, nonce, tag = aes_encrypt(plaintext, key)
    recovered = aes_decrypt(ciphertext, key, nonce, tag)

    assert recovered.decode("utf-8") == plaintext


def test_shamir_split_and_recover():
    secret_bytes = get_random_bytes(32)
    secret_int = int.from_bytes(secret_bytes, "big")

    shares = split_secret(secret_int, n=5, t=3)

    assert len(shares) == 5
    assert len({x for x, _ in shares}) == 5  # identificadores únicos

    recovered = recover_secret(shares[:3], 3)
    assert recovered == secret_int


def test_shamir_rejects_secret_too_large():
    with pytest.raises(ValueError):
        split_secret(shamir_core.PRIME, n=3, t=2)
