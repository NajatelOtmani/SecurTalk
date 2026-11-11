import os

os.environ.setdefault("DATABASE_URL", "sqlite://")     # evite de creer un fichier .db a l'import

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app

PW = "motdepasse-solide"
CLIENT_IP = "203.0.113.9"
INTERNAL = {"X-API-Key": "cle-interne-de-test"}


def make_settings(**kw):
    base = dict(database_url="sqlite://", soc_mode="memory", soc_keys={"auth": "a", "relay": "r"},
                internal_key="cle-interne-de-test", internal_allowed_ips=(CLIENT_IP,),
                heartbeat_seconds=0, fast_hash=True, rate_limit_per_minute=30)
    base.update(kw)
    return Settings(**base)


@pytest.fixture(scope="session")
def rsa_pems():
    """Vraies cles RSA du SDK (1024 bits : rapide, tests seulement)."""
    sdk = pytest.importorskip("securetalk_crypto")
    return [sdk.RSAKeyExchange.generate_keypair(1024) for _ in range(2)]    # (private_pem, public_pem)


@pytest.fixture
def settings():
    return make_settings()


@pytest.fixture
def app(settings):
    return create_app(settings)


@pytest.fixture
def client(app):
    with TestClient(app, client=(CLIENT_IP, 50000)) as c:
        yield c


def types(app, event_type=None):
    ev = app.state.emitter.events
    return [e for e in ev if event_type is None or e["event_type"] == event_type]


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def duo(client, rsa_pems):
    """Alice et Bob inscrits et connectes, avec leurs vraies cles RSA."""
    out = {}
    for nom, (priv, pub) in zip(("alice", "bob"), rsa_pems):
        r = client.post("/auth/register", json={"username": nom, "password": PW, "public_key_pem": pub})
        assert r.status_code == 201, r.text
        uid = r.json()["user_id"]
        t = client.post("/auth/login", json={"username": nom, "password": PW}).json()["token"]
        out[nom] = {"id": uid, "token": t, "priv": priv, "pub": pub}
    return out
