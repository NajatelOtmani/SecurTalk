import json
from PySide6.QtCore import QThread, Signal


class WsThread(QThread):
    """Écoute le WebSocket du backend ; se reconnecte seul (1 s, 2 s, 4 s... 10 s max).
    À chaque reconnexion le backend renvoie les clés et messages en attente (sans doublon)."""
    received = Signal(dict)
    status = Signal(str)  # "up" | "retry" | "down"

    def __init__(self, url):
        super().__init__()
        self.url, self._ws, self._stop = url, None, False

    def run(self):
        delay = 1
        while not self._stop:
            try:
                from websockets.sync.client import connect
                with connect(self.url, open_timeout=5) as ws:
                    self._ws, delay = ws, 1
                    self.status.emit("up")
                    for raw in ws:
                        try:
                            self.received.emit(json.loads(raw))
                        except ValueError:
                            pass
            except Exception:  # noqa: BLE001
                pass
            self._ws = None
            if self._stop:
                break
            self.status.emit("retry")
            for _ in range(int(delay * 10)):
                if self._stop:
                    break
                self.msleep(100)
            delay = min(delay * 2, 10)
        self.status.emit("down")

    def stop(self):
        self._stop = True
        try:
            if self._ws:
                self._ws.close()
        except Exception:  # noqa: BLE001
            pass
        self.wait(2000)
