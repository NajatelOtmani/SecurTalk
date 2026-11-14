import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import storage  # noqa: E402


class Net:
    """Faux backend en mémoire."""
    def __init__(self):
        self.keys, self.pkts, self.pubs, self.rotation_required = [], [], {}, False


@pytest.fixture
def net(tmp_path, monkeypatch):
    def user_dir(u):
        d = tmp_path / u
        d.mkdir(exist_ok=True)
        return d
    monkeypatch.setattr(storage, "user_dir", user_dir)
    return Net()


class FakeClient:
    def __init__(self, net, name, uid):
        import securetalk_crypto as sdk
        self.net, self.username, self.user_id = net, name, uid
        priv, pub = sdk.RSAKeyExchange.generate_keypair()
        storage.save_private_key(name, priv)
        net.pubs[name] = pub

    def public_key(self, u):
        return {"user_id": "x", "public_key_pem": self.net.pubs[u]}

    def exchange_key(self, conv, to, kid, w):
        self.net.keys.append(dict(conversation_id=conv, from_user_id=self.user_id, key_id=kid, wrapped_key_b64=w))
        self.net.rotation_required = False  # le backend remet l'indicateur à zéro

    def send_packet(self, p):
        from api_backend import ApiError
        if self.net.rotation_required:
            raise ApiError("KEY_ROTATION_REQUIRED", "rotation", 409)
        self.net.pkts.append(p)

    def ack(self, i):
        pass


@pytest.fixture
def pair(net):
    from chat_service import ChatService
    ca, cb = FakeClient(net, "alice", "u_a"), FakeClient(net, "bob", "u_b")
    a, b = ChatService(ca), ChatService(cb)
    a.pubkeys["u_b"], b.pubkeys["u_a"] = net.pubs["bob"], net.pubs["alice"]
    return a, b, net
