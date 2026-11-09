import base64

import pytest

from securetalk_crypto import (KeyExchangeError, KeyManager, RSAKeyExchange,
                               decrypt_message, encrypt_message)


def test_wrap_unwrap(paires_rsa, cle):
    (priv_b, pub_b), _ = paires_rsa
    wrapped = RSAKeyExchange.wrap_key(pub_b, cle)
    recu = RSAKeyExchange.unwrap_key(priv_b, wrapped)
    assert recu == cle and recu.key_id == cle.key_id and recu.bits == 256


def test_wrap_deux_fois_different(paires_rsa, cle):
    (_, pub_b), _ = paires_rsa
    assert RSAKeyExchange.wrap_key(pub_b, cle) != RSAKeyExchange.wrap_key(pub_b, cle)


def test_mauvaise_cle_privee(paires_rsa, cle):
    (_, pub_b), (priv_autre, _) = paires_rsa
    with pytest.raises(KeyExchangeError):
        RSAKeyExchange.unwrap_key(priv_autre, RSAKeyExchange.wrap_key(pub_b, cle))


def test_donnees_corrompues(paires_rsa, cle):
    (priv_b, pub_b), _ = paires_rsa
    w = bytearray(base64.b64decode(RSAKeyExchange.wrap_key(pub_b, cle)))
    w[5] ^= 1
    for mauvais in (base64.b64encode(bytes(w)).decode(), "pas du base64 !", "", "AAAA"):
        with pytest.raises(KeyExchangeError):
            RSAKeyExchange.unwrap_key(priv_b, mauvais)


def test_pem_invalides(paires_rsa, cle):
    (priv_b, pub_b), _ = paires_rsa
    with pytest.raises(KeyExchangeError):
        RSAKeyExchange.wrap_key("n'importe quoi", cle)
    with pytest.raises(KeyExchangeError):
        RSAKeyExchange.unwrap_key("n'importe quoi", "AAAA")
    with pytest.raises(KeyExchangeError):   # une cle publique n'est pas une cle privee
        RSAKeyExchange.unwrap_key(pub_b, "AAAA")


@pytest.mark.parametrize("bits", [128, 192, 256])
def test_toutes_tailles_de_cle(paires_rsa, bits):
    (priv_b, pub_b), _ = paires_rsa
    k = KeyManager().generate_key(bits)
    assert RSAKeyExchange.unwrap_key(priv_b, RSAKeyExchange.wrap_key(pub_b, k)) == k


def test_scenario_complet_du_readme(paires_rsa):
    (priv_b, pub_b), _ = paires_rsa
    key = KeyManager().generate_key(256)
    key_chez_b = RSAKeyExchange.unwrap_key(priv_b, RSAKeyExchange.wrap_key(pub_b, key))
    for mode in ("GCM", "CMAC"):
        p = encrypt_message("Bonjour", key, mode, "u_1a", "u_2b", "conv_u_1a_u_2b", counter=1)
        assert decrypt_message(p, key_chez_b) == "Bonjour"


def test_rsa_2048_taille_et_format():
    priv, pub = RSAKeyExchange.generate_keypair(2048)
    assert pub.startswith("-----BEGIN RSA PUBLIC KEY-----")
    assert priv.startswith("-----BEGIN RSA PRIVATE KEY-----")
    k = KeyManager().generate_key(256)
    assert RSAKeyExchange.unwrap_key(priv, RSAKeyExchange.wrap_key(pub, k)) == k


def test_compatible_avec_bibliotheque_standard(cle):
    """Nos PEM sont lus par `cryptography`, et son OAEP dechiffre notre wrap."""
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    priv, pub = RSAKeyExchange.generate_keypair(1024)
    prive_lib = serialization.load_pem_private_key(priv.encode(), password=None)
    serialization.load_pem_public_key(pub.encode())
    brut = prive_lib.decrypt(
        base64.b64decode(RSAKeyExchange.wrap_key(pub, cle)),
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    assert cle.key_bytes in brut and cle.key_id.encode() in brut
