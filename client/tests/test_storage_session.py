from datetime import datetime, timedelta, timezone
import pytest
import storage
from api_backend import BackendClient

PEM = "-----BEGIN PRIVATE KEY-----\nABCDEF\n-----END PRIVATE KEY-----"


@pytest.fixture
def tmp_store(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "user_dir", lambda u: (tmp_path / u).mkdir(exist_ok=True) or tmp_path / u)
    return tmp_path


def test_cle_chiffree_aller_retour(tmp_store):
    storage.save_private_key("alice", PEM, "motdepasse12")
    f = tmp_store / "alice" / "private.pem.enc"
    assert f.exists() and "BEGIN" not in f.read_text() and not (tmp_store / "alice" / "private.pem").exists()
    assert storage.load_private_key("alice", "motdepasse12") == PEM
    assert storage.has_private_key("alice")


def test_mauvais_mot_de_passe_et_mot_de_passe_requis(tmp_store):
    storage.save_private_key("alice", PEM, "motdepasse12")
    with pytest.raises(storage.WrongPassword):
        storage.load_private_key("alice", "autre-mot-de-passe")
    with pytest.raises(storage.PasswordRequired):
        storage.load_private_key("alice")


def test_deux_chiffrements_differents(tmp_store):
    storage.save_private_key("a", PEM, "motdepasse12")
    c1 = (tmp_store / "a" / "private.pem.enc").read_text()
    storage.save_private_key("a", PEM, "motdepasse12")
    assert c1 != (tmp_store / "a" / "private.pem.enc").read_text()  # sel et nonce aléatoires


def test_migration_ancien_fichier_en_clair(tmp_store):
    storage.save_private_key("bob", PEM)  # ancien format
    assert (tmp_store / "bob" / "private.pem").exists()
    assert storage.load_private_key("bob", "motdepasse12") == PEM
    assert not (tmp_store / "bob" / "private.pem").exists()
    assert (tmp_store / "bob" / "private.pem.enc").exists()
    assert storage.load_private_key("bob", "motdepasse12") == PEM


def test_seconds_left():
    c = BackendClient()
    assert c.seconds_left() is None
    c.expires_at = (datetime.now(timezone.utc) + timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert 590 <= c.seconds_left() <= 600
    c.expires_at = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    assert c.seconds_left() < 0
    c.expires_at = "n'importe quoi"
    assert c.seconds_left() is None
