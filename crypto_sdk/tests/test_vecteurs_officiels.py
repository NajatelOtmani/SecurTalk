"""Verifie tes algorithmes du cours contre les vecteurs officiels."""
import os

import pytest

from securetalk_crypto import aes, modes
from securetalk_crypto.kdf import hkdf_sha256


def test_aes_fips197():
    bloc = bytes.fromhex("00112233445566778899aabbccddeeff")
    cas = [
        ("000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a"),
        ("000102030405060708090a0b0c0d0e0f1011121314151617", "dda97ca4864cdfe06eaf70a0ec0d7191"),
        ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "8ea2b7ca516745bfeafc49904b496089"),
    ]
    for cle_hex, attendu in cas:
        ks = aes.expansion_cle(bytes.fromhex(cle_hex))
        c = aes.chiffre_bloc(bloc, ks)
        assert c.hex() == attendu
        assert aes.dechiffre_bloc(c, ks) == bloc


def test_cmac_rfc4493():
    cle = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    msg = bytes.fromhex(
        "6bc1bee22e409f96e93d7e117393172a" "ae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52ef" "f69f2445df4f9b17ad2b417be66c3710")
    vecteurs = [
        (b"", "bb1d6929e95937287fa37d129b756746"),
        (msg[:16], "070a16b46b4d4144f79bdd9dd04a287c"),
        (msg[:40], "dfa66747de9ae63030ca32611497c827"),
        (msg[:64], "51f0bebf7e3b9d92fc49741779363cfe"),
    ]
    for m, attendu in vecteurs:
        assert modes.cmac(m, cle).hex() == attendu


def test_gcm_vecteurs():
    c, t = modes.gcm_chiffre(b"", bytes(16), bytes(12))
    assert t.hex() == "58e2fccefa7e3061367f1d57a4e7455a"
    c, t = modes.gcm_chiffre(bytes(16), bytes(16), bytes(12))
    assert c.hex() == "0388dace60b6a392f328c2b971b2fe78"
    assert t.hex() == "ab6e47d42cec13bdf53a67b21257bddf"
    cle = bytes.fromhex("feffe9928665731c6d6a8f9467308308")
    nonce = bytes.fromhex("cafebabefacedbaddecaf888")
    clair = bytes.fromhex(
        "d9313225f88406e5a55909c5aff5269a" "86a7a9531534f7da2e4c303d8a318a72"
        "1c3c0c95956809532fcf0e2449a6b525" "b16aedf5aa0de657ba637b39")
    aad = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
    c, t = modes.gcm_chiffre(clair, cle, nonce, aad)
    assert t.hex() == "5bc94fbc3221a5db94fae95ae7121a47"
    assert modes.gcm_dechiffre(c, t, cle, nonce, aad) == clair


def test_hkdf_rfc5869():
    ikm = bytes.fromhex("0b" * 22)
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    okm = hkdf_sha256(ikm, info, 42, salt)
    assert okm.hex() == ("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                         "34007208d5b887185865")


def test_cbc_et_padding():
    cle, iv = os.urandom(16), os.urandom(16)
    for n in (0, 1, 15, 16, 17, 100):
        m = os.urandom(n)
        assert modes.cbc_dechiffre(modes.cbc_chiffre(m, cle, iv), cle, iv) == m


def test_contre_bibliotheque_standard():
    """Optionnel : compare avec la lib `cryptography` si elle est installee."""
    ciphers = pytest.importorskip("cryptography.hazmat.primitives.ciphers")
    from cryptography.hazmat.primitives.ciphers import aead
    from cryptography.hazmat.primitives import cmac as lib_cmac
    from cryptography.hazmat.primitives.ciphers import algorithms
    for taille in (16, 24, 32):
        cle, nonce, aad, m = os.urandom(taille), os.urandom(12), os.urandom(20), os.urandom(70)
        c, t = modes.gcm_chiffre(m, cle, nonce, aad)
        assert aead.AESGCM(cle).encrypt(nonce, m, aad) == c + t
        mac = lib_cmac.CMAC(algorithms.AES(cle))
        mac.update(m)
        assert mac.finalize() == modes.cmac(m, cle)
