import pytest

from securetalk_crypto import KeyManager, RSAKeyExchange


@pytest.fixture(scope="session")
def paires_rsa():
    """2 paires RSA 1024 bits (rapide, tests seulement). En vrai : 2048 ou 3072."""
    return RSAKeyExchange.generate_keypair(1024), RSAKeyExchange.generate_keypair(1024)


@pytest.fixture
def cle():
    return KeyManager().generate_key(256)
