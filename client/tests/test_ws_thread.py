import json
import time
import pytest

pytest.importorskip("PySide6")
ws_server = pytest.importorskip("websockets.sync.server")
from PySide6.QtCore import QCoreApplication  # noqa: E402
from ui.ws_thread import WsThread  # noqa: E402


def test_reconnexion_automatique():
    """Le serveur coupe la connexion après chaque message : le client doit se reconnecter seul."""
    count = {"n": 0}

    def handler(ws):
        count["n"] += 1
        ws.send(json.dumps({"type": "message", "n": count["n"]}))

    import threading
    srv = ws_server.serve(handler, "127.0.0.1", 8765)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    app = QCoreApplication.instance() or QCoreApplication([])
    got, states = [], []
    t = WsThread("ws://127.0.0.1:8765/ws?token=t")
    t.received.connect(lambda d: got.append(d["n"]))
    t.status.connect(states.append)
    t.start()
    end = time.time() + 6
    while len(got) < 2 and time.time() < end:
        app.processEvents()
        time.sleep(0.02)
    t.stop()
    srv.shutdown()
    assert got[:2] == [1, 2]
    assert "up" in states and "retry" in states
