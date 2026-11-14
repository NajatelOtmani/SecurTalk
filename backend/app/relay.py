"""RelayServer (guide 4.3) : le relais fait passer les paquets SANS les lire.

Chemin d'un paquet : taille -> jeton -> format Pydantic -> sender = utilisateur du jeton
-> debit -> destinataire -> conversation -> rotation_required -> stockage -> push WebSocket
-> PACKET_ROUTED. Le relais ne journalise jamais ciphertext_b64.
"""
import json
import threading
import time
from collections import deque
from typing import Optional

from fastapi import APIRouter, Depends, Header, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.concurrency import run_in_threadpool
from pydantic import ValidationError
from sqlalchemy import select, update

from app.deps import current_user, get_db
from app.errors import ApiError, AuthFailure
from app.models import Conversation, KeyExchange, PendingMessage, User
from app.schemas import MessagePacket
from app.utils import client_ip, make_conversation_id, other_participant, utcnow


class RateLimiter:
    """Fenetre glissante de 60 s, par utilisateur."""

    def __init__(self, limit, window=60.0):
        self.limit, self.window = limit, window
        self._hits, self._lock = {}, threading.Lock()

    def allow(self, key):
        now = time.monotonic()
        with self._lock:
            q = self._hits.setdefault(key, deque())
            while q and now - q[0] > self.window:
                q.popleft()
            if len(q) >= self.limit:
                return False
            q.append(now)
            return True


class ConnectionManager:
    def __init__(self):
        self._conns = {}

    def connect(self, user_id, ws):
        self._conns.setdefault(user_id, []).append(ws)

    def disconnect(self, user_id, ws):
        lst = self._conns.get(user_id, [])
        if ws in lst:
            lst.remove(ws)
        if not lst:
            self._conns.pop(user_id, None)

    def is_online(self, user_id):
        return bool(self._conns.get(user_id))

    async def send(self, user_id, payload):
        ok = False
        for ws in list(self._conns.get(user_id, [])):
            try:
                await ws.send_json(payload)
                ok = True
            except Exception:
                self.disconnect(user_id, ws)
        return ok

    async def close_user(self, user_id, code=1008):
        for ws in list(self._conns.get(user_id, [])):
            try:
                await ws.close(code=code)
            except Exception:
                pass
            self.disconnect(user_id, ws)


def ensure_conversation(db, a, b):
    cid = make_conversation_id(a, b)
    conv = db.get(Conversation, cid)
    if conv is None:
        x, y = sorted([a, b])
        conv = Conversation(conversation_id=cid, user_a=x, user_b=y, rotation_required=False)
        db.add(conv)
        db.flush()
    return conv


def key_payload(row):
    return {"type": "key", "conversation_id": row.conversation_id, "from_user_id": row.from_user_id,
            "key_id": row.key_id, "wrapped_key_b64": row.wrapped_key_b64}


class RelayService:
    def __init__(self, settings, emitter, auth, session_factory, manager):
        self.s, self.emitter, self.auth = settings, emitter, auth
        self.SessionLocal, self.manager = session_factory, manager
        self.limiter = RateLimiter(settings.rate_limit_per_minute)

    # ---- routage ---------------------------------------------------------
    def _reject(self, ip, reason, user_id=None, extra=None):
        details = {"reason": reason}
        details.update(extra or {})
        self.emitter.emit("relay", "PACKET_REJECTED_UNAUTH", "medium",
                          actor={"user_id": user_id, "username": None, "ip": ip}, details=details)

    def route_packet(self, db, authorization, raw, ip):
        """Retourne (receiver_id, message_id, payload_websocket)."""
        try:
            user = self.auth.authenticate(db, authorization, ip)
        except AuthFailure as e:
            self._reject(ip, e.reason, e.user_id)
            raise
        try:
            obj = json.loads(raw)
            if not isinstance(obj, dict):
                raise ValueError("objet JSON attendu")
            pkt = MessagePacket.model_validate(obj)
        except ValidationError as e:
            champs = sorted({".".join(str(x) for x in err["loc"]) for err in e.errors()})
            raise ApiError(400, "INVALID_FORMAT", "Paquet invalide : " + ", ".join(champs)) from None
        except ValueError:
            raise ApiError(400, "INVALID_FORMAT", "Corps JSON invalide") from None

        if pkt.sender_id != user.id:                       # usurpation d'identite
            self._reject(ip, "sender_mismatch", pkt.sender_id,
                         {"authenticated_user_id": user.id})
            raise ApiError(403, "SENDER_MISMATCH", "sender_id different de l'utilisateur connecte")
        if not self.limiter.allow(user.id):
            self.emitter.emit("relay", "RATE_LIMIT_EXCEEDED", "medium",
                              actor={"user_id": user.id, "username": None, "ip": ip},
                              details={"limit_per_minute": self.s.rate_limit_per_minute})
            raise ApiError(429, "RATE_LIMIT_EXCEEDED", "Trop de messages, reessayez plus tard")
        if pkt.receiver_id == pkt.sender_id:
            raise ApiError(400, "INVALID_RECEIVER", "Le destinataire doit etre different de l'expediteur")
        if db.get(User, pkt.receiver_id) is None:
            raise ApiError(404, "RECEIVER_NOT_FOUND", "Destinataire inconnu")
        if pkt.conversation_id != make_conversation_id(pkt.sender_id, pkt.receiver_id):
            raise ApiError(400, "INVALID_CONVERSATION", "conversation_id incoherent avec sender_id / receiver_id")
        conv = ensure_conversation(db, pkt.sender_id, pkt.receiver_id)
        if conv.rotation_required:
            db.commit()
            raise ApiError(409, "KEY_ROTATION_REQUIRED", "Rotation de cle obligatoire pour cette conversation")
        if db.get(PendingMessage, pkt.message_id) is not None:
            raise ApiError(409, "DUPLICATE_MESSAGE", "message_id deja utilise")
        packet = pkt.model_dump()
        db.add(PendingMessage(message_id=pkt.message_id, conversation_id=pkt.conversation_id,
                              sender_id=pkt.sender_id, receiver_id=pkt.receiver_id,
                              packet_json=json.dumps(packet, separators=(",", ":"))))
        db.commit()
        self.emitter.emit("relay", "PACKET_ROUTED",
                          actor={"user_id": user.id, "username": None, "ip": ip},
                          target={"user_id": pkt.receiver_id, "conversation_id": pkt.conversation_id},
                          details={"message_id": pkt.message_id, "mode": pkt.mode,
                                   "key_id": pkt.key_id, "counter": pkt.counter, "size_bytes": len(raw)})
        return pkt.receiver_id, pkt.message_id, {"type": "message", "packet": packet}

    def ack(self, db, user, message_id, ip):
        row = db.get(PendingMessage, message_id)
        if row is None or row.receiver_id != user.id:
            raise ApiError(404, "MESSAGE_NOT_FOUND", "Message inconnu")
        if row.acked_at is None:                           # idempotent : un seul evenement
            row.acked_at = utcnow()
            if row.delivered_at is None:
                row.delivered_at = row.acked_at
            db.commit()
            self.emitter.emit("relay", "MESSAGE_DELIVERED",
                              actor={"user_id": row.sender_id, "username": None, "ip": ip},
                              target={"user_id": row.receiver_id, "conversation_id": row.conversation_id},
                              details={"message_id": row.message_id})

    # ---- livraison (anti-doublon par "reservation" atomique) -------------
    def claim(self, kind, row_id):
        model, col = (PendingMessage, PendingMessage.message_id) if kind == "message" \
            else (KeyExchange, KeyExchange.id)
        with self.SessionLocal() as db:
            res = db.execute(update(model).where(col == row_id, model.delivered_at.is_(None))
                             .values(delivered_at=utcnow()))
            db.commit()
            return res.rowcount == 1

    def release(self, kind, row_id):
        """Annule la reservation si l'envoi WebSocket a echoue (le paquet sera renvoye plus tard)."""
        model, col = (PendingMessage, PendingMessage.message_id) if kind == "message" \
            else (KeyExchange, KeyExchange.id)
        conditions = [col == row_id]
        if kind == "message":
            conditions.append(PendingMessage.acked_at.is_(None))
        with self.SessionLocal() as db:
            db.execute(update(model).where(*conditions).values(delivered_at=None))
            db.commit()

    async def push_message(self, receiver_id, message_id, payload):
        if not self.manager.is_online(receiver_id):
            return False
        if not await run_in_threadpool(self.claim, "message", message_id):
            return False
        ok = await self.manager.send(receiver_id, payload)
        if not ok:
            await run_in_threadpool(self.release, "message", message_id)
        return ok

    async def push_key(self, receiver_id, row_id, payload):
        if not self.manager.is_online(receiver_id):
            return False
        if not await run_in_threadpool(self.claim, "key", row_id):
            return False
        ok = await self.manager.send(receiver_id, payload)
        if not ok:
            await run_in_threadpool(self.release, "key", row_id)
        return ok

    def list_undelivered(self, user_id):
        """[(kind, id, payload)] : les cles d'abord, puis les messages dans l'ordre d'arrivee."""
        out = []
        with self.SessionLocal() as db:
            for k in db.scalars(select(KeyExchange).where(KeyExchange.to_user_id == user_id,
                                                          KeyExchange.delivered_at.is_(None))
                                .order_by(KeyExchange.id)):
                out.append(("key", k.id, key_payload(k)))
            for m in db.scalars(select(PendingMessage).where(PendingMessage.receiver_id == user_id,
                                                             PendingMessage.delivered_at.is_(None))
                                .order_by(PendingMessage.created_at)):
                out.append(("message", m.message_id, {"type": "message", "packet": json.loads(m.packet_json)}))
        return out


router = APIRouter()


async def _lire_corps(request: Request, limite: int):
    """Lit le corps en flux et refuse (413) au-dela de la taille maximale."""
    cl = request.headers.get("content-length")
    if cl and cl.isdigit() and int(cl) > limite:
        raise ApiError(413, "PACKET_TOO_LARGE", "Paquet trop volumineux")
    data = bytearray()
    async for morceau in request.stream():
        data.extend(morceau)
        if len(data) > limite:
            raise ApiError(413, "PACKET_TOO_LARGE", "Paquet trop volumineux")
    return bytes(data)


@router.post("/messages", status_code=202)
async def post_message(request: Request, authorization: Optional[str] = Header(default=None)):
    app = request.app
    raw = await _lire_corps(request, app.state.settings.max_packet_bytes)
    ip = client_ip(request)

    def travail():
        with app.state.SessionLocal() as db:
            return app.state.relay.route_packet(db, authorization, raw, ip)

    receiver_id, message_id, payload = await run_in_threadpool(travail)
    await app.state.relay.push_message(receiver_id, message_id, payload)
    return {"message_id": message_id}


@router.post("/messages/{message_id}/ack", status_code=204, response_class=Response)
def ack_message(message_id: str, request: Request, user=Depends(current_user), db=Depends(get_db)):
    request.app.state.relay.ack(db, user, message_id, client_ip(request))
    return Response(status_code=204)


@router.get("/conversations/{conversation_id}/status")
def conversation_status(conversation_id: str, user=Depends(current_user), db=Depends(get_db)):
    if other_participant(conversation_id, user.id) is None:
        raise ApiError(403, "FORBIDDEN", "Vous ne faites pas partie de cette conversation")
    conv = db.get(Conversation, conversation_id)
    return {"rotation_required": bool(conv and conv.rotation_required)}


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, token: Optional[str] = None):
    app = websocket.app
    relay = app.state.relay

    def verifier():
        with app.state.SessionLocal() as db:
            try:
                return app.state.auth.authenticate(db, f"Bearer {token}" if token else None, "0.0.0.0").id
            except ApiError:
                return None

    user_id = await run_in_threadpool(verifier)
    if user_id is None:
        await websocket.close(code=1008)                  # refuse la poignee de main
        return
    await websocket.accept()
    app.state.manager.connect(user_id, websocket)
    try:
        for kind, row_id, payload in await run_in_threadpool(relay.list_undelivered, user_id):
            if not await run_in_threadpool(relay.claim, kind, row_id):
                continue                                   # deja livre en direct entre-temps
            try:
                await websocket.send_json(payload)
            except Exception:
                await run_in_threadpool(relay.release, kind, row_id)
                raise
        while True:
            texte = await websocket.receive_text()
            if texte == "ping":
                await websocket.send_text("pong")
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        app.state.manager.disconnect(user_id, websocket)
