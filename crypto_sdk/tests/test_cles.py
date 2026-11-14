import pytest

from securetalk_crypto import KeyManager, SessionKey, UnknownKeyError


def test_repr_sans_octets(cle):
    texte = repr(cle) + str(cle) + f"{cle}"
    assert cle.key_bytes.hex() not in texte
    assert texte.startswith("SessionKey(key_id=k_")
    assert "bits=256" in texte


def test_tailles_et_ids_uniques():
    km = KeyManager()
    ids = set()
    for bits in (128, 192, 256):
        k = km.generate_key(bits)
        assert k.bits == bits and len(k.key_bytes) == bits // 8
        ids.add(k.key_id)
    assert len(ids) == 3
    with pytest.raises(ValueError):
        km.generate_key(100)


def test_rotation_et_ancienne_cle_gardee():
    t = [1000.0]
    km = KeyManager(retention_seconds=300, clock=lambda: t[0])
    k1 = km.rotate_key("conv")
    k2 = km.rotate_key("conv")
    assert k1.key_id != k2.key_id and km.current_key("conv") is k2
    assert km.get_key("conv", k1.key_id) is k1       # ancienne encore valable
    t[0] += 301
    with pytest.raises(UnknownKeyError):             # expiree
        km.get_key("conv", k1.key_id)
    assert km.get_key("conv", k2.key_id) is k2
    with pytest.raises(UnknownKeyError):
        km.get_key("conv", "k_inconnu")


def test_cycle_128_192_256():
    km = KeyManager()
    km.add_key("c", km.generate_key(128))
    assert [km.rotate_key("c").bits for _ in range(4)] == [192, 256, 128, 192]


def test_should_rotate_par_age():
    t = [0.0]
    km = KeyManager(clock=lambda: t[0])
    k = km.generate_key(256)
    assert not km.should_rotate(k)
    t[0] = 3600
    assert km.should_rotate(k)


def test_wipe(cle):
    cle.wipe()
    assert cle.key_bytes == bytes(32)


def test_cle_invalide():
    with pytest.raises(ValueError):
        SessionKey("k_1", 256, b"court")
