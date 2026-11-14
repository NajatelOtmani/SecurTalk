import re
import storage
from api_backend import ApiError, BackendClient
from PySide6.QtCore import Signal
from .worker import Worker
from PySide6.QtWidgets import (QFrame, QHBoxLayout, QLabel, QLineEdit, QPushButton,
                               QVBoxLayout, QWidget)


class LoginWindow(QWidget):
    logged_in = Signal(object)  # BackendClient connecté

    def __init__(self, profile="alice"):
        super().__init__()
        self.setObjectName("root")
        self.setWindowTitle("SecureTalk AI")
        self.resize(920, 580)
        self.register_mode = False
        root = QHBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        brand = QFrame()
        brand.setObjectName("brand")
        brand.setFixedWidth(400)
        b = QVBoxLayout(brand)
        b.setContentsMargins(40, 48, 40, 40)
        logo = QLabel("🛡  SecureTalk AI")
        logo.setStyleSheet("font-size:20px; font-weight:700; color:white;")
        tag = QLabel("La messagerie d'entreprise\nqui protège chaque conversation.")
        tag.setStyleSheet("font-size:24px; font-weight:700; color:white;")
        b.addWidget(logo)
        b.addSpacing(40)
        b.addWidget(tag)
        b.addSpacing(24)
        for t in ["Chiffrement AES-GCM / CMAC de bout en bout",
                  "Analyse anti-phishing par IA avant l'envoi",
                  "Surveillance Mini-SOC en continu"]:
            l = QLabel("✓  " + t)
            l.setStyleSheet("color:rgba(255,255,255,0.85); padding:4px 0;")
            b.addWidget(l)
        b.addStretch()
        note = QLabel("Le SOC ne reçoit que des métadonnées,\njamais vos messages ni vos clés.")
        note.setStyleSheet("color:rgba(255,255,255,0.7); font-size:12px;")
        b.addWidget(note)
        root.addWidget(brand)

        right = QVBoxLayout()
        right.setContentsMargins(70, 0, 70, 0)
        right.addStretch()
        self.title = QLabel("Connexion")
        self.title.setObjectName("title")
        sub = QLabel("Accédez à votre espace sécurisé")
        sub.setObjectName("muted")
        self.user = QLineEdit(profile)
        self.user.setPlaceholderText("Nom d'utilisateur")
        self.pwd = QLineEdit()
        self.pwd.setPlaceholderText("Mot de passe (10 caractères minimum)")
        self.pwd.setEchoMode(QLineEdit.EchoMode.Password)
        self.pwd.returnPressed.connect(self.submit)
        self.error = QLabel("")
        self.error.setObjectName("error")
        self.btn = QPushButton("Se connecter")
        self.btn.setObjectName("primary")
        self.btn.clicked.connect(self.submit)
        self.switch = QPushButton("Pas de compte ? Créer un compte")
        self.switch.setObjectName("link")
        self.switch.clicked.connect(self.toggle)
        for w in (self.title, sub):
            right.addWidget(w)
        right.addSpacing(18)
        for w in (self.user, self.pwd, self.error, self.btn, self.switch):
            right.addWidget(w)
            right.addSpacing(6)
        right.addStretch()
        root.addLayout(right, 1)

    def toggle(self):
        self.register_mode = not self.register_mode
        self.title.setText("Créer un compte" if self.register_mode else "Connexion")
        self.btn.setText("S'inscrire" if self.register_mode else "Se connecter")
        self.switch.setText("Déjà un compte ? Se connecter" if self.register_mode
                            else "Pas de compte ? Créer un compte")
        self.error.setText("")

    def submit(self):
        u, p = self.user.text().strip().lower(), self.pwd.text()
        # mêmes règles que le backend (guide 4.2)
        if not re.fullmatch(r"[a-z0-9_]{3,32}", u):
            return self.error.setText("Nom : 3 à 32 caractères (lettres, chiffres, _).")
        if len(p) < 10:
            return self.error.setText("Mot de passe : 10 caractères minimum.")
        self.busy(True, "Génération des clés…" if self.register_mode else "Connexion…")
        client = BackendClient()

        def job():
            if self.register_mode:
                priv, pub = storage.generate_keypair()
                client.register(u, p, pub)
                storage.save_private_key(u, priv, p)  # chiffrée avec le mot de passe
            client.login(u, p)
            if not storage.has_private_key(u):
                client.logout()
                raise ApiError("NO_LOCAL_KEY", "")
            try:  # déchiffre la clé (ou chiffre l'ancien fichier en clair au passage)
                client.private_pem = storage.load_private_key(u, p)
            except storage.WrongPassword:
                client.logout()
                raise ApiError("WRONG_LOCAL_PASSWORD", "")
            return client

        self._w = Worker(job)
        self._w.ok.connect(self.logged_in.emit)
        self._w.fail.connect(self.on_fail)
        self._w.start()

    def busy(self, on, text=None):
        self.btn.setEnabled(not on)
        self.btn.setText(text if on else ("S'inscrire" if self.register_mode else "Se connecter"))

    def on_fail(self, e):
        self.busy(False)
        msgs = {"INVALID_CREDENTIALS": "Identifiants incorrects.",
                "ACCOUNT_LOCKED": "Compte verrouillé par la sécurité. Contactez l'administrateur.",
                "BACKEND_UNREACHABLE": "Serveur injoignable. Le backend est-il lancé (port 8000) ?",
                "WRONG_LOCAL_PASSWORD": "Mot de passe incorrect pour la clé privée de cet appareil.",
                "NO_LOCAL_KEY": "Clé privée introuvable sur cet appareil : compte créé ailleurs."}
        if isinstance(e, ApiError):
            self.error.setText(msgs.get(e.code) or e.message or e.code)
        elif isinstance(e, ImportError):
            self.error.setText("SDK crypto absent : py -m pip install -e ../crypto_sdk")
        else:
            self.error.setText(f"Erreur inattendue : {type(e).__name__}")
