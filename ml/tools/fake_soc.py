"""FAUX SOC pour tester seule (règle d'or n°3 : ne jamais attendre l'autre).
  uvicorn tools.fake_soc:app --port 8002
Imite POST /soc/events (202/400/401) et garde les événements en mémoire : GET /soc/events pour les voir.
"""
import os

from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse

app = FastAPI(title="FAUX SOC (tests)")
EVENTS = []
REQUIRED = {"event_id", "timestamp", "source", "event_type", "severity", "actor"}
FORBIDDEN = {"message", "text", "plaintext", "content", "body", "key", "session_key",
             "private_key", "password", "token", "ciphertext"}


def _has_forbidden(o):
    if isinstance(o, dict):
        return any(k.lower() in FORBIDDEN or _has_forbidden(v) for k, v in o.items())
    if isinstance(o, list):
        return any(_has_forbidden(v) for v in o)
    return isinstance(o, str) and len(o) > 200


@app.post("/soc/events", status_code=202)
async def receive(request: Request, x_api_key: str = Header(default="")):
    expected = os.environ.get("SOC_KEY_PHISHING", "")
    if not x_api_key or (expected and x_api_key != expected):
        return JSONResponse(status_code=401, content={"error": "INVALID_API_KEY", "message": "clé invalide"})
    ev = await request.json()
    if not REQUIRED <= set(ev):
        return JSONResponse(status_code=400, content={"error": "INVALID_FORMAT",
                            "message": f"champs manquants : {sorted(REQUIRED - set(ev))}"})
    if _has_forbidden(ev):
        return JSONResponse(status_code=400, content={"error": "PRIVACY_VIOLATION",
                            "message": "champ interdit dans l'événement"})
    EVENTS.append(ev)
    print(f"[SOC] {ev['source']:9s} {ev['event_type']:24s} {ev['severity']}")
    return {"event_id": ev["event_id"]}


@app.get("/soc/events")
def list_events():
    return EVENTS
