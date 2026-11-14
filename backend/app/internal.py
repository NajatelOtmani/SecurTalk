"""Commandes du SOC vers le backend (guide 2.8 / 4.4).

Protegees par X-API-Key = INTERNAL_KEY_SOC_TO_BACKEND ET par une liste d'IP autorisees.
Chaque commande : action idempotente + ligne d'audit_log + evenement correspondant.
"""
import hmac
import json
from typing import Optional

from fastapi import APIRouter, Depends, Header, Request
from fastapi.concurrency import run_in_threadpool
from sqlalchemy import or_, update

from app.errors import ApiError
from app.models import AuditLog, Conversation
from app.utils import client_ip, utcnow

router = APIRouter(prefix="/internal")


def require_internal(request: Request, x_api_key: Optional[str] = Header(default=None)):
    s = request.app.state.settings
    ip = request.client.host if request.client else ""
    if ip not in s.internal_allowed_ips:
        raise ApiError(403, "FORBIDDEN_IP", "Adresse non autorisee")
    # cle absente cote serveur => tout est refuse (jamais de cle vide acceptee)
    if not s.internal_key or not x_api_key or not hmac.compare_digest(x_api_key, s.internal_key):
        raise ApiError(401, "INVALID_API_KEY", "Cle interne invalide")


def _audit(db, action, obj, details, ip):
    db.add(AuditLog(timestamp=utcnow(), actor="soc", action=action, object=obj,
                    details_json=json.dumps({**details, "ip": ip})))


@router.post("/accounts/{user_id}/lock", dependencies=[Depends(require_internal)])
async def lock(user_id: str, request: Request):
    app, ip = request.app, client_ip(request)

    def travail():
        with app.state.SessionLocal() as db:
            _, changed = app.state.auth.set_status(db, user_id, "locked", ip)
            _audit(db, "lock_account", user_id, {"changed": changed}, ip)
            db.commit()
            return changed

    changed = await run_in_threadpool(travail)
    await app.state.manager.close_user(user_id)           # coupe les WebSocket ouverts
    return {"user_id": user_id, "status": "locked", "changed": changed}


@router.post("/accounts/{user_id}/unlock", dependencies=[Depends(require_internal)])
def unlock(user_id: str, request: Request):
    app, ip = request.app, client_ip(request)
    with app.state.SessionLocal() as db:
        _, changed = app.state.auth.set_status(db, user_id, "active", ip)
        _audit(db, "unlock_account", user_id, {"changed": changed}, ip)
        db.commit()
    return {"user_id": user_id, "status": "active", "changed": changed}


@router.post("/conversations/{conversation_id}/force-rotation", dependencies=[Depends(require_internal)])
def force_rotation(conversation_id: str, request: Request):
    app, ip = request.app, client_ip(request)
    if not conversation_id.startswith("conv_") or len(conversation_id) > 210:
        raise ApiError(400, "INVALID_CONVERSATION", "conversation_id invalide")
    with app.state.SessionLocal() as db:
        conv = db.get(Conversation, conversation_id)
        if conv is None:
            raise ApiError(404, "CONVERSATION_NOT_FOUND", "Conversation inconnue")
        changed = not conv.rotation_required
        conv.rotation_required = True
        conv.updated_at = utcnow()
        _audit(db, "force_rotation", conversation_id, {"changed": changed}, ip)
        db.commit()
    return {"conversation_id": conversation_id, "rotation_required": True, "changed": changed}


@router.post("/accounts/{user_id}/force-rotation-all", dependencies=[Depends(require_internal)])
def force_rotation_all(user_id: str, request: Request):
    app, ip = request.app, client_ip(request)
    with app.state.SessionLocal() as db:
        res = db.execute(update(Conversation)
                         .where(or_(Conversation.user_a == user_id, Conversation.user_b == user_id),
                                Conversation.rotation_required.is_(False))
                         .values(rotation_required=True, updated_at=utcnow()))
        _audit(db, "force_rotation_all", user_id, {"conversations_marked": res.rowcount}, ip)
        db.commit()
    return {"user_id": user_id, "conversations_marked": res.rowcount}
