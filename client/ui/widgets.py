from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (QDialog, QFrame, QHBoxLayout, QLabel, QProgressBar,
                               QPushButton, QVBoxLayout, QWidget)
from .theme import BADGE, C


def make_badge(label):
    b = QLabel(f"● {'Non analysé' if label == 'Unscanned' else label}")
    col = BADGE[label]
    b.setStyleSheet(f"color:{col}; font-size:11px; font-weight:700; background:transparent;")
    return b


class Bubble(QWidget):
    def __init__(self, text, mine, time, label="Safe"):
        super().__init__()
        row = QHBoxLayout(self)
        row.setContentsMargins(0, 0, 0, 0)
        box = QFrame()
        box.setObjectName("bubble_mine" if mine else "bubble_other")
        box.setMaximumWidth(440)
        v = QVBoxLayout(box)
        v.setContentsMargins(14, 10, 14, 8)
        v.setSpacing(4)
        t = QLabel(text)
        t.setWordWrap(True)
        t.setTextFormat(Qt.TextFormat.PlainText)  # jamais de lien cliquable (guide 7.5)
        t.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        v.addWidget(t)
        if label in ("Suspicious", "Phishing") and not mine:
            w = QLabel("⚠ Signalé par l'IA : n'ouvrez aucun lien")
            w.setStyleSheet(f"color:{BADGE[label]}; font-size:11px; font-weight:600; background:transparent;")
            v.addWidget(w)
        meta = QHBoxLayout()
        meta.setSpacing(8)
        if label and (label != "Safe" or not mine):
            meta.addWidget(make_badge(label))
        meta.addStretch()
        tm = QLabel(time + ("  ✓✓ Livré" if mine else ""))
        tm.setStyleSheet("font-size:11px; color:rgba(255,255,255,0.65); background:transparent;")
        meta.addWidget(tm)
        v.addLayout(meta)
        if mine:
            row.addStretch()
            row.addWidget(box)
        else:
            row.addWidget(box)
            row.addStretch()


class Toast(QFrame):
    def __init__(self, parent):
        super().__init__(parent)
        self.setObjectName("card")
        self.setStyleSheet(f"QFrame#card{{border-left:4px solid {C['cyan']};}}")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 12, 16, 12)
        self.msg = QLabel()
        lay.addWidget(self.msg)
        self.hide()
        self._timer = QTimer(self, singleShot=True, timeout=self.hide)

    def show_message(self, text):
        self.msg.setText(text)
        self.adjustSize()
        p = self.parent()
        self.move(p.width() - self.width() - 24, 20)
        self.show()
        self.raise_()
        self._timer.start(3200)


class PhishingModal(QDialog):
    """block=True : politique 'block' (message refusé). block=False : avertissement + 'Envoyer quand même'."""

    def __init__(self, parent, label, score, reasons, block):
        super().__init__(parent)
        self.setWindowTitle("Analyse de sécurité")
        self.setModal(True)
        self.setMinimumWidth(440)
        col = BADGE[label]
        v = QVBoxLayout(self)
        v.setContentsMargins(26, 24, 26, 22)
        v.setSpacing(14)
        title = QLabel("Message bloqué : phishing probable" if block else "Ce message semble suspect")
        title.setStyleSheet(f"font-size:18px; font-weight:700; color:{col};")
        v.addWidget(title)
        v.addWidget(make_badge(label))
        top = QHBoxLayout()
        top.addWidget(QLabel("Score de risque"))
        top.addStretch()
        sc = QLabel(f"{score:.2f}")
        sc.setStyleSheet(f"font-weight:700; color:{col};")
        top.addWidget(sc)
        v.addLayout(top)
        bar = QProgressBar()
        bar.setRange(0, 100)
        bar.setValue(int(score * 100))
        bar.setStyleSheet(f"QProgressBar::chunk{{background:{col};}}")
        v.addWidget(bar)
        h = QLabel("POURQUOI ?")
        h.setObjectName("h2")
        v.addWidget(h)
        for r in reasons:
            l = QLabel("•  " + r)
            l.setWordWrap(True)
            v.addWidget(l)
        note = QLabel("Politique : le message n'est pas envoyé." if block
                      else "Vous pouvez annuler ou envoyer malgré l'avertissement.")
        note.setObjectName("muted")
        v.addWidget(note)
        btns = QHBoxLayout()
        btns.addStretch()
        if block:
            ok = QPushButton("Compris, ne pas envoyer")
            ok.setObjectName("danger")
            ok.clicked.connect(self.reject)
            btns.addWidget(ok)
        else:
            cancel = QPushButton("Annuler")
            cancel.setObjectName("primary")
            cancel.clicked.connect(self.reject)
            force = QPushButton("Envoyer quand même")
            force.setObjectName("ghost")
            force.clicked.connect(self.accept)
            btns.addWidget(force)
            btns.addWidget(cancel)
        v.addLayout(btns)
