"""Scénarios du guide 7.6 sur la vraie fenêtre (mode hors écran) avec faux backend et IA simulée."""
import copy
import json
import os
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import pytest

pytest.importorskip("PySide6")
from PySide6.QtWidgets import QApplication  # noqa: E402
import api_ml  # noqa: E402
import soc_events  # noqa: E402
import ui.main_window as mw  # noqa: E402
from chat_service import ChatService  # noqa: E402
from conftest import FakeClient  # noqa: E402


class UiClient(FakeClient):
    token = "t"

    def ws_url(self):
        return "ws://127.0.0.1:1/ws"

    def logout(self):
        pass

    def health(self):
        return {"status": "ok"}


def verdict(label, score, codes=()):
    return {"label": label, "score": score, "model_version": "test",
            "reasons": [{"code": c, "text": c} for c in codes]}


@pytest.fixture
def ui(net, tmp_path, monkeypatch):
    app = QApplication.instance() or QApplication([])
    monkeypatch.setattr(soc_events, "_default", soc_events.SocEmitter(mode="file", base_dir=tmp_path, async_=False))
    monkeypatch.setattr(api_ml, "health", lambda: {"model_version": "test"})
    me, peer = UiClient(net, "alice", "u_a"), UiClient(net, "bob", "u_b")
    win = mw.MainWindow(me)
    win.service.pubkeys["u_b"] = net.pubs["bob"]
    win.names["u_b"] = "bob"
    win.side.add_conv("u_b", "bob")
    win.side.select("u_b")

    def wait(cond, t=3.0):
        end = time.time() + t
        while not cond() and time.time() < end:
            app.processEvents()
            time.sleep(0.01)
        for _ in range(10):
            app.processEvents()

    def events():
        f = tmp_path / "events.jsonl"
        return [json.loads(x)["event_type"] for x in f.read_text().splitlines()] if f.exists() else []

    yield win, net, peer, wait, events
    win.ws.stop()
    win.close()
    for w in list(win._workers):
        w.wait(2000)


def test_safe_est_envoye(ui, monkeypatch):
    win, net, _, wait, ev = ui
    monkeypatch.setattr(api_ml, "analyze", lambda *a: verdict("Safe", 0.05))
    win.handle_send("Bonjour")
    wait(lambda: net.pkts)
    assert len(net.pkts) == 1 and "Bonjour" not in str(net.pkts[0])


def test_phishing_bloque(ui, monkeypatch):
    win, net, _, wait, ev = ui
    monkeypatch.setattr(api_ml, "analyze", lambda *a: verdict("Phishing", 0.94, ["URL_BRAND_IMITATION"]))
    monkeypatch.setattr(mw.PhishingModal, "exec", lambda self: 0)
    win.handle_send("Voir http://micros0ft-login.com/verify")
    wait(lambda: "MESSAGE_BLOCKED" in ev())
    assert not net.pkts and {"WARNING_SHOWN", "MESSAGE_BLOCKED"} <= set(ev())
    assert win.chat.input.isEnabled()


def test_suspect_confirme_puis_annule(ui, monkeypatch):
    win, net, _, wait, ev = ui
    monkeypatch.setattr(api_ml, "analyze", lambda *a: verdict("Suspicious", 0.5, ["TEXT_URGENCY"]))
    monkeypatch.setattr(mw.PhishingModal, "exec", lambda self: 0)  # annuler
    win.handle_send("c'est urgent")
    wait(lambda: "WARNING_SHOWN" in ev())
    assert not net.pkts and "USER_OVERRODE_WARNING" not in ev()
    monkeypatch.setattr(mw.PhishingModal, "exec", lambda self: 1)  # envoyer quand même
    win.handle_send("c'est urgent")
    wait(lambda: net.pkts)
    assert len(net.pkts) == 1 and "USER_OVERRODE_WARNING" in ev()


def test_ia_en_panne_repli_et_variante_stricte(ui, monkeypatch):
    win, net, _, wait, ev = ui

    def down(*a):
        raise api_ml.MlUnavailable()
    monkeypatch.setattr(api_ml, "analyze", down)
    win.handle_send("salut")
    wait(lambda: net.pkts)
    assert len(net.pkts) == 1 and win.history["u_b"][-1][3] == "Unscanned"  # T9 : envoyé avec avertissement
    win.policy["ml_unavailable"] = "block"
    win.handle_send("refusé")
    wait(lambda: "MESSAGE_BLOCKED" in ev())
    assert len(net.pkts) == 1


def test_paquet_falsifie_et_rejoue(ui):
    win, net, peer, wait, ev = ui
    b = ChatService(peer)
    b.pubkeys["u_a"] = net.pubs["alice"]
    pkt = b.send_text("u_a", "salut")
    win.on_ws({"type": "key", **net.keys[-1]})
    bad = copy.deepcopy(b.send_text("u_a", "x"))
    bad["counter"] = 99
    win.on_ws({"type": "message", "packet": bad})
    assert "GCM_AUTH_FAIL" in ev()
    win.on_ws({"type": "message", "packet": pkt})
    wait(lambda: win.history.get("u_b"))
    win.on_ws({"type": "message", "packet": pkt})
    assert "REPLAY_DETECTED" in ev() and win.replays == 1
