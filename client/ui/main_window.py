import uuid
from datetime import datetime
from PySide6.QtCore import QSize, Qt, QTimer, Signal
from PySide6.QtWidgets import (QComboBox, QFrame, QHBoxLayout, QLabel, QLineEdit, QListWidget,
                               QListWidgetItem, QMainWindow, QPushButton, QScrollArea,
                               QVBoxLayout, QWidget)
from .theme import C
from .widgets import Bubble, PhishingModal, Toast
from .worker import Worker
from .ws_thread import WsThread
from api_backend import ApiError
import api_ml
from soc_events import emit_event
from api_ml import extract_urls
from policy import load as load_policy
from chat_service import ChatService, local_time, conversation_id, format_age


CONVS = [("Bob Martin", "Parfait, je t'envoie ça demain.", "10:42", True),
         ("Sara El Idrissi", "Réunion confirmée à 15h", "09:15", True),
         ("Équipe Support", "Nouveau lien de vérification", "Hier", False),
         ("Youssef Amrani", "Merci !", "Lun", False)]

DEMO = [("Bonjour Bob, tu as vu le dossier client ?", True, "10:38", "Safe"),
        ("Oui, je le termine cet après-midi.", False, "10:40", "Safe"),
        ("Parfait, je t'envoie ça demain.", True, "10:42", "Safe"),
        ("Votre compte sera suspendu. Vérifiez-le : micros0ft-login.com/verify", False, "10:44", "Phishing")]


def initials(name):
    return "".join(p[0] for p in name.split()[:2]).upper()


def avatar(name, size=36):
    a = QLabel(initials(name))
    a.setObjectName("avatar")
    a.setFixedSize(size, size)
    a.setAlignment(Qt.AlignmentFlag.AlignCenter)
    a.setStyleSheet(f"border-radius:{size // 2}px;")
    return a


def card(title):
    f = QFrame()
    f.setObjectName("card")
    v = QVBoxLayout(f)
    v.setContentsMargins(14, 12, 14, 12)
    v.setSpacing(8)
    h = QLabel(title.upper())
    h.setObjectName("h2")
    v.addWidget(h)
    return f, v


def kv(label, value, color=None):
    w = QWidget()
    h = QHBoxLayout(w)
    h.setContentsMargins(0, 0, 0, 0)
    a = QLabel(label)
    a.setObjectName("muted")
    b = QLabel(value)
    b.setStyleSheet(f"font-weight:600; color:{color or C['text']};")
    h.addWidget(a)
    h.addStretch()
    h.addWidget(b)
    return w, b


class Sidebar(QFrame):
    contact_requested = Signal(str)
    selected = Signal(str)

    def __init__(self, username):
        super().__init__()
        self.setObjectName("sidebar")
        self.setFixedWidth(290)
        self.items = {}
        v = QVBoxLayout(self)
        v.setContentsMargins(0, 18, 0, 14)
        logo = QLabel("🛡  SecureTalk AI")
        logo.setStyleSheet("font-size:16px; font-weight:700; padding-left:18px;")
        v.addWidget(logo)
        v.addSpacing(10)
        self.search = QLineEdit()
        self.search.setPlaceholderText("➕  Ajouter un contact (nom) + Entrée")
        self.search.returnPressed.connect(self._add)
        sw = QHBoxLayout()
        sw.setContentsMargins(14, 0, 14, 0)
        sw.addWidget(self.search)
        v.addLayout(sw)
        self.list = QListWidget()
        self.list.currentItemChanged.connect(
            lambda cur, _old: cur and self.selected.emit(cur.data(Qt.ItemDataRole.UserRole)))
        v.addWidget(self.list, 1)
        prof = QFrame()
        prof.setObjectName("card")
        h = QHBoxLayout(prof)
        h.setContentsMargins(12, 10, 12, 10)
        h.addWidget(avatar(username))
        col = QVBoxLayout()
        col.setSpacing(0)
        col.addWidget(QLabel(username.capitalize()))
        st = QLabel("● Connecté")
        st.setStyleSheet(f"color:{C['safe']}; font-size:11px;")
        col.addWidget(st)
        h.addLayout(col)
        h.addStretch()
        pw = QHBoxLayout()
        pw.setContentsMargins(14, 0, 14, 0)
        pw.addWidget(prof)
        v.addLayout(pw)

    def _add(self):
        name = self.search.text().strip()
        if name:
            self.contact_requested.emit(name)
            self.search.clear()

    def add_conv(self, peer_id, name):
        if peer_id in self.items:
            self.items[peer_id]["name"].setText(name)
            self.items[peer_id]["av"].setText(initials(name))
            return
        it = QListWidgetItem()
        it.setData(Qt.ItemDataRole.UserRole, peer_id)
        it.setSizeHint(QSize(250, 62))
        self.list.addItem(it)
        w = QWidget()
        h = QHBoxLayout(w)
        h.setContentsMargins(10, 6, 10, 6)
        av = avatar(name, 38)
        h.addWidget(av)
        col = QVBoxLayout()
        col.setSpacing(1)
        n = QLabel(name)
        n.setStyleSheet("font-weight:600;")
        last = QLabel("")
        last.setObjectName("muted")
        col.addWidget(n)
        col.addWidget(last)
        h.addLayout(col, 1)
        tm = QLabel("")
        tm.setObjectName("muted")
        h.addWidget(tm, 0, Qt.AlignmentFlag.AlignTop)
        self.list.setItemWidget(it, w)
        self.items[peer_id] = {"item": it, "name": n, "last": last, "time": tm, "av": av}

    def select(self, peer_id):
        self.list.setCurrentItem(self.items[peer_id]["item"])

    def set_last(self, peer_id, text, time):
        if peer_id in self.items:
            self.items[peer_id]["last"].setText(text[:34])
            self.items[peer_id]["time"].setText(time)


class ChatView(QWidget):
    def __init__(self, on_send):
        super().__init__()
        self.on_send = on_send
        v = QVBoxLayout(self)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)
        head = QFrame()
        head.setObjectName("chathead")
        hh = QHBoxLayout(head)
        hh.setContentsMargins(22, 14, 22, 14)
        self.av = avatar("?", 40)
        hh.addWidget(self.av)
        col = QVBoxLayout()
        col.setSpacing(0)
        self.nm = nm = QLabel("Aucune conversation")
        nm.setStyleSheet("font-size:15px; font-weight:700;")
        self.sub = sub = QLabel("Ajoutez un contact pour commencer")
        sub.setObjectName("muted")
        col.addWidget(nm)
        col.addWidget(sub)
        hh.addLayout(col)
        hh.addStretch()
        self.chip = chip = QLabel("🔒 Chiffré · AES-GCM")
        chip.setObjectName("chip")
        chip.setStyleSheet(f"background: rgba(16,185,129,0.15); color:{C['safe']}; border-radius:9px; padding:3px 10px; font-size:12px; font-weight:600;")
        hh.addWidget(chip)
        v.addWidget(head)
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        inner = QWidget()
        self.msgs = QVBoxLayout(inner)
        self.msgs.setContentsMargins(24, 18, 24, 18)
        self.msgs.setSpacing(12)
        self.msgs.addStretch()
        inner.setStyleSheet('background: transparent;')
        self.scroll.viewport().setAutoFillBackground(False)
        self.scroll.setWidget(inner)
        v.addWidget(self.scroll, 1)
        comp = QFrame()
        comp.setObjectName("composer")
        cv = QVBoxLayout(comp)
        cv.setContentsMargins(22, 12, 22, 12)
        row = QHBoxLayout()
        self.input = QLineEdit()
        self.input.setPlaceholderText("Écrire un message sécurisé…")
        self.input.returnPressed.connect(self.send)
        btn = QPushButton("Envoyer  ➤")
        btn.setObjectName("primary")
        btn.clicked.connect(self.send)
        row.addWidget(self.input)
        row.addWidget(btn)
        cv.addLayout(row)
        hint = QLabel("Chiffré de bout en bout : le serveur ne voit jamais le texte")
        hint.setObjectName("muted")
        cv.addWidget(hint)
        v.addWidget(comp)

    def clear(self):
        while self.msgs.count() > 1:
            w = self.msgs.takeAt(0).widget()
            if w:
                w.deleteLater()

    def set_secure(self, mode_label):
        self.chip.setText(f"🔒 Chiffré · {mode_label}")

    def set_header(self, name, conv=None):
        self.nm.setText(name)
        self.sub.setText(conv or "Contact")
        self.sub.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.av.setText(initials(name))

    def add_message(self, text, mine, time=None, label="Safe"):
        time = time or datetime.now().strftime("%H:%M")
        self.msgs.insertWidget(self.msgs.count() - 1, Bubble(text, mine, time, label))
        QTimer.singleShot(0, lambda: self.scroll.verticalScrollBar().setValue(
            self.scroll.verticalScrollBar().maximum()))

    def send(self):
        text = self.input.text().strip()
        if text:
            self.on_send(text)


class SecurityPanel(QFrame):
    def __init__(self, on_rotate):
        super().__init__()
        self.setObjectName("secpanel")
        self.setFixedWidth(310)
        self.key_n = 3
        v = QVBoxLayout(self)
        v.setContentsMargins(16, 18, 16, 14)
        v.setSpacing(12)
        t = QLabel("Sécurité de la conversation")
        t.setStyleSheet("font-size:15px; font-weight:700;")
        v.addWidget(t)
        c, cl = card("Connexion & IA")
        for a, b, col in [("Backend", "● Vérification…", C["muted"]), ("WebSocket", "● Vérification…", C["muted"]),
                          ("Protection IA", "● Vérification…", C["muted"])]:
            w_, lab_ = kv(a, b, col)
            cl.addWidget(w_)
            setattr(self, {"Backend": "l_backend", "WebSocket": "l_ws", "Protection IA": "l_ia"}[a], lab_)
        v.addWidget(c)
        c, cl = card("Chiffrement")
        self.mode = QComboBox()
        self.mode.addItems(["AES-GCM", "AES-CBC + CMAC"])
        cl.addWidget(self.mode)
        w, self.key_id = kv("Key ID", "k_0003")
        cl.addWidget(w)
        w, self.bits = kv("Taille", "256 bits")
        cl.addWidget(w)
        w, self.key_status = kv("Statut de la clé", "—")
        cl.addWidget(w)
        w, self.key_age = kv("Âge de la clé", "—")
        cl.addWidget(w)
        w, self.replay_lbl = kv("Anti-rejeu", "● Actif · 0 rejeu bloqué", C["safe"])
        cl.addWidget(w)
        w, self.counter = kv("Dernier compteur", "—")
        cl.addWidget(w)
        rot = QPushButton("Renouveler la clé")
        rot.setObjectName("ghost")
        rot.clicked.connect(on_rotate)
        cl.addWidget(rot)
        v.addWidget(c)
        c, self.ev = card("Événements récents")
        v.addWidget(c)
        v.addStretch()

    def rotate(self):
        self.key_n += 1
        self.key_id.setText(f"k_{self.key_n:04d}")

    def _kstatus(self, text, color):
        self.key_status.setText(text)
        self.key_status.setStyleSheet(f"font-weight:600; color:{color};")

    def show_key(self, d):
        if isinstance(d, tuple):
            d = {"key_id": d[0], "bits": d[1]}
        if not d:
            for lab in (self.key_id, self.bits, self.key_age):
                lab.setText("—")
            return self._kstatus("—", C["muted"])
        self.key_id.setText(d["key_id"])
        self.bits.setText(f"{d['bits']} bits")
        self.key_age.setText(format_age(d.get("age_s")))
        if d.get("needs_rotation"):
            self._kstatus("● À renouveler", C["warn"])
        else:
            self._kstatus("● Active" + (" (réception)" if d.get("direction") == "réception" else ""), C["safe"])

    def set_backend(self, up):
        self.l_backend.setText("● Connecté" if up else "● Injoignable")
        self.l_backend.setStyleSheet(f"font-weight:600; color:{C['safe'] if up else C['danger']};")

    def set_replays(self, n):
        self.replay_lbl.setText(f"● Actif · {n} rejeu{'x' if n > 1 else ''} bloqué{'s' if n > 1 else ''}")
        self.replay_lbl.setStyleSheet(f"font-weight:600; color:{C['danger'] if n else C['safe']};")

    def set_ia(self, version, up):
        self.l_ia.setText(f"● {version}" if up else "● Indisponible")
        self.l_ia.setStyleSheet(f"font-weight:600; color:{C['safe'] if up else C['danger']};")

    def set_ws(self, state):
        txt, col = {"up": ("● Actif", C["safe"]), "retry": ("● Reconnexion…", C["warn"])}.get(
            state, ("● Déconnecté", C["danger"]))
        self.l_ws.setText(txt)
        self.l_ws.setStyleSheet(f"font-weight:600; color:{col};")

    def add_event(self, text, color=None):
        l = QLabel(f"{datetime.now():%H:%M}  {text}")
        l.setStyleSheet(f"font-size:12px; color:{color or C['muted']};")
        self.ev.insertWidget(1, l)
        while self.ev.count() > 7:
            self.ev.takeAt(self.ev.count() - 1).widget().deleteLater()


class MainWindow(QMainWindow):
    session_expired = Signal(str)

    def __init__(self, client):
        super().__init__()
        self.client = client
        try:
            self.service = ChatService(client)
        except ImportError:
            self.service = None
        username = client.username
        self.setWindowTitle(f"SecureTalk AI : {username}")
        self.resize(1280, 780)
        self.names, self.history, self.current, self._workers = {}, {}, None, []
        self.counters = {}  # dernier compteur vu par conversation
        root = QWidget()
        root.setObjectName("root")
        h = QHBoxLayout(root)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(0)
        self.side = Sidebar(username)
        self.chat = ChatView(self.handle_send)
        self.panel = SecurityPanel(self.rotate_key)
        h.addWidget(self.side)
        h.addWidget(self.chat, 1)
        h.addWidget(self.panel)
        self.setCentralWidget(root)
        self.toast = Toast(root)
        self.panel.mode.currentIndexChanged.connect(self.on_mode)
        self.panel.show_key(None)
        if self.service is None:
            QTimer.singleShot(400, lambda: self.toast.show_message("SDK crypto absent : pip install -e ../crypto_sdk"))
        self.side.contact_requested.connect(self.add_contact)
        self.side.selected.connect(self.select_peer)
        self.panel.add_event("LOGIN_SUCCESS", C["safe"])
        self.policy, self.ml_up = load_policy(), False
        self._ml_timer = QTimer(self, interval=15000, timeout=self.check_ml)
        self._ml_timer.start()
        self.replays = 0
        self._expired, self._warned = False, False
        self._sess_timer = QTimer(self, interval=30000, timeout=self.check_session)
        self._sess_timer.start()
        self._age_timer = QTimer(self, interval=30000, timeout=lambda: self.refresh_key(self.current))
        self._age_timer.start()
        QTimer.singleShot(300, self.check_ml)
        self.ws = WsThread(client.ws_url())
        self.ws.status.connect(self.panel.set_ws)
        self.ws.received.connect(self.on_ws)
        self.ws.start()

    def run_async(self, fn, ok=None, fail=None):
        w = Worker(fn)
        if ok:
            w.ok.connect(ok)
        w.fail.connect(fail or self.on_error)
        w.finished.connect(lambda: self._workers.remove(w) if w in self._workers else None)
        self._workers.append(w)
        w.start()

    def _busy(self, on):
        self.chat.input.setEnabled(not on)
        if not on:
            self.chat.input.setFocus()

    def set_ml(self, up, version=None):
        self.ml_up = up
        self.panel.set_ia(version, up)

    def check_ml(self):
        self.run_async(self.client.health, ok=lambda d: self.panel.set_backend(True),
                       fail=lambda e: self.panel.set_backend(False))
        self.run_async(api_ml.health, ok=lambda d: self.set_ml(True, d.get("model_version", "?")),
                       fail=lambda e: self.set_ml(False))

    def check_session(self):
        left = self.client.seconds_left() if hasattr(self.client, "seconds_left") else None
        if left is None:
            return
        if left <= 0:
            self._expire()
        elif left <= 300 and not self._warned:
            self._warned = True
            self.toast.show_message(f"⏱ Votre session expire dans {int(left // 60) + 1} min")

    def _expire(self):
        if self._expired:
            return
        self._expired = True
        self._sess_timer.stop()
        self.ws.stop()
        self.session_expired.emit(self.client.username)

    def refresh_key(self, pid):
        if self.service and pid == self.current:
            self.panel.show_key(self.service.key_details(pid))

    # ----- événements vers le SOC (métadonnées seulement) -----
    def _me(self):
        return {"user_id": self.client.user_id, "username": self.client.username, "ip": None}

    def client_event(self, etype, pid, details):
        emit_event("client", etype, actor=self._me(), details=details,
                   target={"user_id": pid, "conversation_id": conversation_id(self.client.user_id, pid)})

    def crypto_event(self, etype, pkt):
        """Émis par le client du RECEVEUR : actor = expéditeur du paquet, target = moi (guide 2.3)."""
        d = {k: str(pkt[k])[:64] for k in ("message_id", "mode", "key_id") if pkt.get(k) is not None}
        if isinstance(pkt.get("counter"), int):
            d["counter"] = pkt["counter"]
        sender = pkt.get("sender_id")
        emit_event("crypto", etype, details=d,
                   actor={"user_id": str(sender)[:64] if sender else None, "username": None, "ip": None},
                   target={"user_id": self.client.user_id,
                           "conversation_id": str(pkt.get("conversation_id") or "")[:80] or None})

    def key_event(self, pid, reason):
        info = self.service.key_info(pid) or (None, None)
        emit_event("crypto", "KEY_ROTATED", actor=self._me(),
                   target={"user_id": pid, "conversation_id": conversation_id(self.client.user_id, pid)},
                   details={"key_id": info[0], "bits": info[1], "reason": reason})

    def on_mode(self, idx):
        if self.service:
            self.service.mode = "GCM" if idx == 0 else "CMAC"
        self.chat.set_secure("AES-GCM" if idx == 0 else "AES-CBC + CMAC")

    def on_error(self, e):
        self._busy(False)
        if getattr(e, "status", 0) == 401:  # jeton refusé : session expirée
            return self._expire()
        msgs = {"BACKEND_UNREACHABLE": "Serveur injoignable", "RATE_LIMIT_EXCEEDED": "Trop de messages, patientez",
                "KEY_ROTATION_REQUIRED": "Rotation de clé exigée (étape 6)",
                "peer_unknown": "Ajoutez ce contact par son nom pour lui écrire"}
        code = getattr(e, "code", "") or (e.args[0] if isinstance(e, KeyError) and e.args else "")
        txt = msgs.get(code, getattr(e, "message", "") or type(e).__name__)
        self.toast.show_message("⚠ " + txt)

    def closeEvent(self, ev):
        self.ws.stop()
        for w in list(self._workers):  # laisse finir les appels réseau en cours
            w.wait(1500)
        self.client.logout()
        super().closeEvent(ev)

    # ----- contacts -----
    def add_contact(self, username):
        username = username.lower()
        if username == self.client.username:
            return self.toast.show_message("C'est vous !")
        self.run_async(lambda: self.client.public_key(username),
                       ok=lambda d: self._contact_ok(username, d),
                       fail=self._contact_fail)

    def _contact_fail(self, e):
        if getattr(e, "status", 0) == 401:
            return self._expire()
        self.toast.show_message("Utilisateur introuvable")

    def _contact_ok(self, username, d):
        pid = d["user_id"]
        self.names[pid] = username
        if self.service:
            self.service.pubkeys[pid] = d["public_key_pem"]
        self.side.add_conv(pid, username)
        self.history.setdefault(pid, [])
        self.side.select(pid)
        self.select_peer(pid)  # rafraîchit le nom si le contact était affiché par son identifiant

    def select_peer(self, pid):
        self.current = pid
        self.chat.clear()
        self.chat.set_header(self.names.get(pid, pid), conversation_id(self.client.user_id, pid))
        if self.service:
            self.refresh_key(pid)
        self.panel.counter.setText(str(self.counters.get(pid, "—")))
        for text, mine, t, lab in self.history.get(pid, []):
            self.chat.add_message(text, mine, t, lab)

    # ----- réception -----
    def on_ws(self, msg):
        if self.service is None:
            return
        kind = msg.get("type")
        if kind == "key":
            data = msg if "wrapped_key_b64" in msg else msg.get("key", {})
            try:
                kid = self.service.receive_key(data)
                self.panel.add_event(f"CLÉ REÇUE {kid}", C["cyan"])
            except Exception:  # noqa: BLE001
                self.panel.add_event("KEY_EXCHANGE_FAIL", C["danger"])
                self.crypto_event("KEY_EXCHANGE_FAIL", {"sender_id": data.get("from_user_id"),
                                                        "conversation_id": data.get("conversation_id"),
                                                        "key_id": data.get("key_id")})
                self.toast.show_message("⚠ Échange de clé invalide")
            return
        if kind != "message":
            return
        pkt = msg["packet"]
        try:
            text = self.service.read(pkt)
        except Exception as e:  # noqa: BLE001
            name = type(e).__name__
            if name == "AuthTagError":
                self.panel.add_event(f"{pkt.get('mode', 'GCM')}_AUTH_FAIL", C["danger"])
                self.crypto_event("CMAC_AUTH_FAIL" if pkt.get("mode") == "CMAC" else "GCM_AUTH_FAIL", pkt)
                self.toast.show_message("⛔ Message invalide ignoré (tag incorrect)")
            elif name == "ReplayError":
                self.panel.add_event("REPLAY_DETECTED", C["danger"])
                self.replays += 1
                self.panel.set_replays(self.replays)
                self.crypto_event("REPLAY_DETECTED", pkt)
                self.toast.show_message("⛔ Paquet rejoué ignoré")
            else:
                self.panel.add_event("CLÉ INCONNUE", C["warn"])
                self.toast.show_message("⚠ Clé manquante : message ignoré")
            return
        if self.ml_up:  # bonus guide 7.3 : on analyse aussi ce qu'on reçoit
            self.run_async(
                lambda: api_ml.analyze(pkt["message_id"], pkt["sender_id"], self.client.user_id,
                                       pkt["conversation_id"], text, extract_urls(text)),
                ok=lambda r: self._deliver(pkt, text, r["label"]),
                fail=lambda e: self._deliver(pkt, text, None))
        else:
            self._deliver(pkt, text, None)

    def _deliver(self, pkt, text, label):
        sender, t = pkt["sender_id"], local_time(pkt.get("timestamp"))
        self.names.setdefault(sender, sender)
        self.side.add_conv(sender, self.names[sender])
        self.history.setdefault(sender, []).append((text, False, t, label))
        self.side.set_last(sender, text, t)
        self.counters[sender] = pkt.get("counter", "—")
        if self.current is None:
            self.side.select(sender)
        elif self.current == sender:
            self.chat.add_message(text, False, t, label)
            self.panel.counter.setText(str(self.counters[sender]))
            self.refresh_key(sender)
        else:
            self.toast.show_message(f"Nouveau message de {self.names[sender]}")
        self.run_async(lambda: self.service.ack(pkt), fail=lambda e: None)
        self.panel.add_event("MESSAGE_REÇU" if label in (None, "Safe") else f"MESSAGE_REÇU ({label})",
                             C["safe"] if label in (None, "Safe") else C["danger"])

    # ----- envoi -----
    def rotate_key(self):
        if not (self.service and self.current):
            return self.toast.show_message("Ouvrez d'abord une conversation")
        pid = self.current

        def done(key):
            self.refresh_key(pid)
            self.panel.add_event("KEY_ROTATED", C["cyan"])
            self.key_event(pid, "manual")
            self.toast.show_message("🔒 Conversation sécurisée : clé renouvelée")

        self.run_async(lambda: self.service.rotate(pid), ok=done)

    def handle_send(self, text):
        if not self.current or not self.service:
            return self.toast.show_message("Ajoutez d'abord un contact")
        if len(text) > 4000:
            return self.toast.show_message("Message trop long (4000 caractères maximum)")
        pid, mid = self.current, str(uuid.uuid4())
        conv = conversation_id(self.client.user_id, pid)
        self._busy(True)
        self.run_async(
            lambda: api_ml.analyze(mid, self.client.user_id, pid, conv, text, extract_urls(text)),
            ok=lambda r: self._verdict(text, pid, r),
            fail=lambda e: self._ml_down(text, pid))

    def _verdict(self, text, pid, r):
        self.set_ml(True, r.get("model_version", "?"))
        label, score = r["label"], float(r["score"])
        if label == "Safe":
            return self._sent(text, "Safe", pid)
        reasons = [x.get("text", "") for x in r.get("reasons", [])] or ["Score élevé du modèle"]
        block = label == "Phishing" and self.policy["phishing_policy"] == "block"
        det = {"message_id": r.get("message_id"), "score": score, "label": label, "text_length": len(text),
               "reason_codes": [x["code"] for x in r.get("reasons", []) if x.get("code")][:10]}
        ok = PhishingModal(self, label, score, reasons, block).exec()
        self.panel.add_event("WARNING_SHOWN", C["warn"])
        self.client_event("WARNING_SHOWN", pid, det)
        if block:
            self._busy(False)
            self.panel.add_event("MESSAGE_BLOCKED", C["danger"])
            self.client_event("MESSAGE_BLOCKED", pid, det)
            self.toast.show_message("⛔ Message bloqué par la protection IA")
        elif ok:
            self.panel.add_event("USER_OVERRODE_WARNING", C["warn"])
            self.client_event("USER_OVERRODE_WARNING", pid, det)
            self._sent(text, label, pid)
        else:
            self._busy(False)

    def _ml_down(self, text, pid):
        """Repli (guide 7.2) : choix écrit dans policy.json -> ml_unavailable."""
        self.set_ml(False)
        self.panel.add_event("WARNING_SHOWN (ml_unavailable)", C["warn"])
        self.client_event("WARNING_SHOWN", pid, {"reason": "ml_unavailable", "text_length": len(text)})
        if self.policy["ml_unavailable"] == "block":
            self._busy(False)
            self.client_event("MESSAGE_BLOCKED", pid, {"reason": "ml_unavailable", "text_length": len(text)})
            return self.toast.show_message("⛔ IA indisponible : envoi refusé par la politique")
        self.toast.show_message("⚠ Message non analysé (IA indisponible)")
        self._sent(text, "Unscanned", pid)

    def _sent(self, text, label, pid):
        def done(packet):
            self._busy(False)
            t = local_time(None)
            self.history.setdefault(pid, []).append((text, True, t, label))
            self.side.set_last(pid, text, t)
            if self.current == pid:
                self.chat.add_message(text, True, t, label)
                self.chat.input.clear()
            self.counters[pid] = packet["counter"]
            self.panel.counter.setText(str(packet["counter"]))
            self.refresh_key(pid)
            self.panel.add_event("PACKET_ROUTED", C["muted"])
            if self.service.last_rotated:
                self.panel.add_event("KEY_ROTATED", C["cyan"])
                self.key_event(pid, "soc_order")
                self.toast.show_message("🔒 Conversation sécurisée : clé renouvelée")

        self.run_async(lambda: self.service.send_text(pid, text), ok=done)
