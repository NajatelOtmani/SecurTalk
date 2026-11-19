from PySide6.QtCore import QThread, Signal


class Worker(QThread):
    """Exécute fn() hors du thread de l'interface (réseau, génération RSA)."""
    ok = Signal(object)
    fail = Signal(object)

    def __init__(self, fn):
        super().__init__()
        self.fn = fn

    def run(self):
        try:
            self.ok.emit(self.fn())
        except Exception as e:  # noqa: BLE001
            self.fail.emit(e)
