"""AuthService (guide 4.2) + routes /auth et /users.

- Mots de passe : Argon2. Jetons : 32 octets aleatoires, seul leur hash SHA-256 est stocke (1 h).
- Meme erreur pour 'utilisateur inconnu' et 'mauvais mot de passe'.
- AUCUN verrouillage automatique ici : c'est le SOC qui decide (via /internal).
"""
import hashlib
import re
import secrets
import threading
from collections import deque
from datetime import timedelta
from typing import Optional

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, VerifyMismatchError
from fastapi import APIRouter, Depends, Header, Request, Response
from sqlalchemy import delete, select

from app.deps import current_user, get_db
from app.errors import ApiError, AuthFailure
from app.models import Session as SessionRow
from app.models import User
from app.schemas import LoginIn, RegisterIn
from app.utils import client_ip, iso, utcnow

USERNAME_RE = re.compile(r"^[a-z0-9_]{3,32}$")
PEM_RE = re.compile(r"^-----BEGIN (RSA )?PUBLIC KEY-----\s+[A-Za-z0-9+/=\s]+-----END (RSA )?PUBLIC KEY-----\s*$")
FAIL_WINDOW = 600     # secondes : fenetre du compteur attempt_number


def hash_token(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class AuthService:
    def __init__(self, settings, emitter):
        self.s = settings
        self.emitter = emitter
        self.ph = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1) if settings.fast_hash \
            else PasswordHasher()
        self._dummy_hash = self.ph.hash(secrets.token_urlsafe(16))   # egalise le temps de reponse
        self._fails = {}
        self._lock = threading.Lock()

    # ---- utilitaires -----------------------------------------------------
    def _verify(self, hash_, password):
        try:
            return self.ph.verify(hash_, password)
        except (VerifyMismatchError, VerificationError, ValueError):
            return False

    def _count_failure(self, username):
        now = utcnow().timestamp()
        with self._lock:
            q = self._fails.setdefault(username, deque())
            while q and now - q[0] > FAIL_WINDOW:
                q.popleft()
            q.append(now)
            if len(self._fails) > 5000:
                self._fails = {k: v for k, v in self._fails.items() if v and now - v[-1] <= FAIL_WINDOW}
            return len(q)

    def _reset_failures(self, username):
        with self._lock:
            self._fails.pop(username, None)

    # ---- inscription / connexion ----------------------------------------
    def register(self, db, username, password, public_key_pem, ip):
        uname = (username or "").strip().lower()
        if not USERNAME_RE.match(uname):
            raise ApiError(400, "INVALID_USERNAME", "Nom d'utilisateur : 3 a 32 caracteres (lettres, chiffres, _)")
        if not isinstance(password, str) or not (10 <= len(password) <= 128):
            raise ApiError(400, "INVALID_PASSWORD", "Mot de passe : 10 a 128 caracteres")
        if not PEM_RE.match(public_key_pem or ""):
            raise ApiError(400, "INVALID_PUBLIC_KEY", "public_key_pem doit etre une cle publique PEM")
        if db.scalar(select(User.id).where(User.username == uname)):
            raise ApiError(409, "USERNAME_TAKEN", "Ce nom d'utilisateur existe deja")
        uid = None
        for _ in range(10):
            candidat = "u_" + secrets.token_hex(4)
            if not db.get(User, candidat):
                uid = candidat
                break
        if uid is None:                                   # pragma: no cover
            raise ApiError(500, "ID_GENERATION_FAILED", "Reessayez")
        db.add(User(id=uid, username=uname, password_hash=self.ph.hash(password),
                    status="active", public_key_pem=public_key_pem.strip() + "\n"))
        db.commit()
        self.emitter.emit("auth", "REGISTER_SUCCESS", actor={"user_id": uid, "username": uname, "ip": ip},
                          target={"user_id": uid})
        return uid

    def login(self, db, username, password, ip):
        uname = username.strip().lower() if isinstance(username, str) else ""
        shown = (uname[:64] or None)
        user = db.scalar(select(User).where(User.username == uname)) if USERNAME_RE.match(uname) else None
        ok = self._verify(user.password_hash if user else self._dummy_hash,
                          password if isinstance(password, str) else "")
        if user is None or not ok:
            n = self._count_failure(uname or "?")
            self.emitter.emit("auth", "LOGIN_FAIL", "low",
                              actor={"user_id": None, "username": shown, "ip": ip},
                              target={"user_id": user.id if user else None, "conversation_id": None},
                              details={"reason": "bad_password" if user else "unknown_user",
                                       "attempt_number": n})
            raise ApiError(401, "INVALID_CREDENTIALS", "Identifiants invalides")
        if user.status == "locked":
            n = self._count_failure(uname)
            self.emitter.emit("auth", "LOGIN_FAIL", "low",
                              actor={"user_id": None, "username": uname, "ip": ip},
                              target={"user_id": user.id, "conversation_id": None},
                              details={"reason": "account_locked", "attempt_number": n})
            raise ApiError(403, "ACCOUNT_LOCKED", "Compte verrouille")
        self._reset_failures(uname)
        now = utcnow()
        db.execute(delete(SessionRow).where(SessionRow.expires_at < now - timedelta(days=1)))
        token = secrets.token_urlsafe(32)
        expires = now + timedelta(seconds=self.s.token_ttl_seconds)
        db.add(SessionRow(token_hash=hash_token(token), user_id=user.id, ip=ip, expires_at=expires))
        db.commit()
        self.emitter.emit("auth", "LOGIN_SUCCESS", actor={"user_id": user.id, "username": uname, "ip": ip},
                          target={"user_id": user.id})
        return {"token": token, "user_id": user.id, "expires_at": iso(expires)}

    def logout(self, db, user, authorization, ip):
        token = authorization.split(" ", 1)[1].strip()
        db.execute(delete(SessionRow).where(SessionRow.token_hash == hash_token(token)))
        db.commit()
        self.emitter.emit("auth", "LOGOUT", actor={"user_id": user.id, "username": user.username, "ip": ip},
                          target={"user_id": user.id})

    # ---- verification du jeton ------------------------------------------
    def authenticate(self, db, authorization: Optional[str], ip):
        if not authorization:
            raise AuthFailure("missing_token")
        parts = authorization.split(" ", 1)
        if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
            raise AuthFailure("invalid_token")
        sess = db.get(SessionRow, hash_token(parts[1].strip()))
        if sess is None:
            raise AuthFailure("invalid_token")
        if sess.expires_at <= utcnow():
            self.emitter.emit("auth", "SESSION_EXPIRED", actor={"user_id": sess.user_id, "username": None, "ip": ip},
                              target={"user_id": sess.user_id})
            raise AuthFailure("expired_token", user_id=sess.user_id)
        user = db.get(User, sess.user_id)
        if user is None:
            raise AuthFailure("invalid_token")
        if user.status == "locked":
            raise AuthFailure("invalid_token", status=403, code="ACCOUNT_LOCKED",
                              message="Compte verrouille", user_id=user.id)
        return user

    # ---- commandes du SOC (utilisees par /internal) ---------------------
    def set_status(self, db, user_id, status, ip):
        """Idempotent. Retourne (user, changed)."""
        user = db.get(User, user_id)
        if user is None:
            raise ApiError(404, "USER_NOT_FOUND", "Utilisateur inconnu")
        if user.status == status:
            return user, False
        user.status = status
        if status == "locked":
            db.execute(delete(SessionRow).where(SessionRow.user_id == user_id))
        db.commit()
        etype = "ACCOUNT_LOCKED" if status == "locked" else "ACCOUNT_UNLOCKED"
        self.emitter.emit("auth", etype, actor={"user_id": None, "username": "soc", "ip": ip},
                          target={"user_id": user_id}, details={"reason": "soc_command"})
        return user, True


router = APIRouter()


@router.post("/auth/register", status_code=201)
def register(body: RegisterIn, request: Request, db=Depends(get_db)):
    uid = request.app.state.auth.register(db, body.username, body.password, body.public_key_pem,
                                          client_ip(request))
    return {"user_id": uid}


@router.post("/auth/login")
def login(body: LoginIn, request: Request, db=Depends(get_db)):
    return request.app.state.auth.login(db, body.username, body.password, client_ip(request))


@router.post("/auth/logout", status_code=204, response_class=Response)
def logout(request: Request, authorization: Optional[str] = Header(default=None),
           user=Depends(current_user), db=Depends(get_db)):
    request.app.state.auth.logout(db, user, authorization, client_ip(request))
    return Response(status_code=204)


@router.get("/users/{username}/publickey")
@router.get("/users/{username}/public-key", include_in_schema=False)   # alias (guide 7.2)
def public_key(username: str, db=Depends(get_db), user=Depends(current_user)):
    row = db.scalar(select(User).where(User.username == username.strip().lower()))
    if row is None:
        raise ApiError(404, "USER_NOT_FOUND", "Utilisateur inconnu")
    return {"user_id": row.id, "public_key_pem": row.public_key_pem}
