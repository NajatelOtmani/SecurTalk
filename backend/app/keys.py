"""Echange de cles (guide 2.7). Le backend stocke temporairement des cles enveloppees en
RSA-OAEP : il ne peut pas les ouvrir (il ne connait aucune cle privee)."""
from fastapi import APIRouter, Depends, Request
from sqlalchemy import select

from app.deps import current_user, get_db
from app.errors import ApiError
from app.models import KeyExchange, User
from app.relay import ensure_conversation, key_payload
from app.schemas import KeyExchangeIn
from app.utils import make_conversation_id, utcnow

router = APIRouter()


@router.post("/keys/exchange", status_code=202)
async def exchange(body: KeyExchangeIn, request: Request, user=Depends(current_user), db=Depends(get_db)):
    if body.to_user_id == user.id:
        raise ApiError(400, "INVALID_RECEIVER", "Destinataire invalide")
    if db.get(User, body.to_user_id) is None:
        raise ApiError(404, "RECEIVER_NOT_FOUND", "Destinataire inconnu")
    if body.conversation_id != make_conversation_id(user.id, body.to_user_id):
        raise ApiError(400, "INVALID_CONVERSATION", "conversation_id incoherent")
    conv = ensure_conversation(db, user.id, body.to_user_id)
    if conv.rotation_required:
        # une rotation n'est valide que si la cle est NOUVELLE (key_id jamais envoye par cet utilisateur)
        deja = db.scalar(select(KeyExchange.id).where(KeyExchange.conversation_id == body.conversation_id,
                                                      KeyExchange.from_user_id == user.id,
                                                      KeyExchange.key_id == body.key_id))
        if deja is not None:
            db.rollback()
            raise ApiError(409, "KEY_ROTATION_REQUIRED", "Une nouvelle cle (nouveau key_id) est requise")
        conv.rotation_required = False
    conv.updated_at = utcnow()
    row = KeyExchange(conversation_id=body.conversation_id, from_user_id=user.id, to_user_id=body.to_user_id,
                      key_id=body.key_id, wrapped_key_b64=body.wrapped_key_b64)
    db.add(row)
    db.commit()
    await request.app.state.relay.push_key(body.to_user_id, row.id, key_payload(row))
    return {"status": "accepted"}


@router.get("/keys/pending")
def pending(request: Request, user=Depends(current_user), db=Depends(get_db)):
    """Cles en attente pour moi. Les cles renvoyees sont marquees livrees (pas de doublon)."""
    relay = request.app.state.relay
    out = []
    for k in db.scalars(select(KeyExchange).where(KeyExchange.to_user_id == user.id,
                                                  KeyExchange.delivered_at.is_(None))
                        .order_by(KeyExchange.id)).all():
        if relay.claim("key", k.id):
            out.append({"conversation_id": k.conversation_id, "from_user_id": k.from_user_id,
                        "key_id": k.key_id, "wrapped_key_b64": k.wrapped_key_b64})
    return out
