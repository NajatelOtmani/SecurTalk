"""Service IA anti-phishing (contrat 2.10). Port 8001.
Lancer : cd ml && uvicorn service.main:app --host 127.0.0.1 --port 8001
CONFIDENTIALITÉ : on ne journalise ni ne stocke jamais `text`.
"""
import asyncio
import logging
import os
import time
from contextlib import asynccontextmanager, suppress

from fastapi import BackgroundTasks, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from .analyzer import PhishingDetector
from .config import MODEL_VERSION
from .model import load_if_available
from .schemas import AnalyzeRequest, AnalysisResult, Reason
from .soc_client import emit_scan_event, heartbeat_loop

log = logging.getLogger("securetalk.ml")
ml_model = load_if_available()                 # None => mode règles seules
detector = PhishingDetector(model=ml_model)    # chargé UNE fois au démarrage (8.7)
ACTIVE_VERSION = ml_model.version if ml_model else MODEL_VERSION


@asynccontextmanager
async def lifespan(_app: FastAPI):
    try:
        interval = float(os.environ.get("HEARTBEAT_SECONDS", "60"))
    except ValueError:
        interval = 60.0
    task = asyncio.create_task(heartbeat_loop(interval, lambda: ACTIVE_VERSION))   # signal de vie (2.3)
    try:
        yield
    finally:
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task


app = FastAPI(title="SecureTalk AI - Service anti-phishing", lifespan=lifespan)


@app.exception_handler(RequestValidationError)
async def bad_format(_: Request, exc: RequestValidationError):
    # Contrat 2.1 : erreur = {"error": "CODE", "message": "..."} avec HTTP 400
    fields = sorted({str(p) for e in exc.errors() for p in e["loc"][1:] if isinstance(p, str)})
    msg = (f"Champs invalides ou manquants : {', '.join(fields)}" if fields
           else "Corps de la requête illisible : JSON valide encodé en UTF-8 attendu")
    return JSONResponse(status_code=400, content={"error": "INVALID_FORMAT", "message": msg})


_HTTP_CODES = {400: "INVALID_FORMAT", 401: "UNAUTHORIZED", 403: "FORBIDDEN", 404: "NOT_FOUND",
               405: "METHOD_NOT_ALLOWED", 409: "CONFLICT", 413: "PAYLOAD_TOO_LARGE", 429: "TOO_MANY_REQUESTS"}


@app.exception_handler(StarletteHTTPException)
async def http_error(_: Request, exc: StarletteHTTPException):
    code = _HTTP_CODES.get(exc.status_code, "HTTP_ERROR")
    msg = "Corps de la requête illisible : JSON valide encodé en UTF-8 attendu" \
        if exc.status_code == 400 else str(exc.detail)
    return JSONResponse(status_code=exc.status_code, content={"error": code, "message": msg})


@app.get("/health")
def health():
    return {"status": "ok", "model_version": ACTIVE_VERSION}


@app.post("/v1/analyze", response_model=AnalysisResult)
def analyze(req: AnalyzeRequest, background: BackgroundTasks):
    start = time.perf_counter()
    domains = []
    try:
        d = detector.analyze(req.text, req.urls)
        score, label, domains = d.score, d.label, d.url_domains
        reasons = [Reason(code=c, text=t) for c, t in d.reasons]
    except Exception as exc:  # jamais de 500 (8.7) ; on ne logge QUE le type d'erreur
        log.error("analysis_failed message_id=%s error=%s", req.message_id, type(exc).__name__)
        score, label, reasons = 0.40, "Suspicious", []   # prudence : ni Safe, ni blocage

    log.info("analyzed message_id=%s score=%.2f label=%s", req.message_id, score, label)
    # Événement SOC en tâche de fond : la réponse part d'abord, l'envoi ne la ralentit pas (8.7).
    background.add_task(emit_scan_event, message_id=req.message_id, sender_id=req.sender_id,
                        receiver_id=req.receiver_id, conversation_id=req.conversation_id,
                        score=score, label=label, reason_codes=[r.code for r in reasons],
                        url_domains=domains, text_length=len(req.text))
    return AnalysisResult(message_id=req.message_id, score=score, label=label,
                          reasons=reasons, model_version=ACTIVE_VERSION,
                          latency_ms=int((time.perf_counter() - start) * 1000))
