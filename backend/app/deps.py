from typing import Optional

from fastapi import Depends, Header, Request

from app.utils import client_ip


def get_db(request: Request):
    db = request.app.state.SessionLocal()
    try:
        yield db
    finally:
        db.close()


def current_user(request: Request, authorization: Optional[str] = Header(default=None),
                 db=Depends(get_db)):
    """Utilisateur du jeton Bearer, sinon 401 (ou 403 ACCOUNT_LOCKED)."""
    return request.app.state.auth.authenticate(db, authorization, client_ip(request))
