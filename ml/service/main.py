"""Service IA anti-phishing (contrat 2.10). Port 8001.
Lancer : cd ml && uvicorn service.main:app --host 127.0.0.1 --port 8001
CONFIDENTIALITÉ : on ne journalise ni ne stocke jamais `text`.
"""
import logging
import time

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from .analyzer import PhishingDetector
from .config import MODEL_VERSION
from .schemas import AnalyzeRequest, AnalysisResult, Reason

log = logging.getLogger("securetalk.ml")
app = FastAPI(title="SecureTalk AI - Service anti-phishing")
detector = PhishingDetector()          # chargé UNE fois au démarrage (8.7)


@app.exception_handler(RequestValidationError)
async def bad_format(_: Request, exc: RequestValidationError):
    fields = sorted({".".join(str(p) for p in e["loc"][1:]) for e in exc.errors()})
    return JSONResponse(status_code=400, content={
        "error": "INVALID_FORMAT",
        "message": f"Champs invalides ou manquants : {', '.join(fields)}"})


@app.get("/health")
def health():
    return {"status": "ok", "model_version": MODEL_VERSION}


@app.post("/v1/analyze", response_model=AnalysisResult)
def analyze(req: AnalyzeRequest):
    start = time.perf_counter()
    try:
        d = detector.analyze(req.text, req.urls)
        score, label = d.score, d.label
        reasons = [Reason(code=c, text=t) for c, t in d.reasons]
    except Exception as exc:  # jamais de 500 (8.7) ; on ne logge QUE le type d'erreur
        log.error("analysis_failed message_id=%s error=%s", req.message_id, type(exc).__name__)
        score, label, reasons = 0.40, "Suspicious", []   # prudence : ni Safe, ni blocage

    log.info("analyzed message_id=%s score=%.2f label=%s", req.message_id, score, label)
    # Étape 7 : émettre l'événement SOC en tâche de fond (score, label, reason_codes,
    # url_domains, text_length) -- jamais le texte.
    return AnalysisResult(message_id=req.message_id, score=score, label=label,
                          reasons=reasons, model_version=MODEL_VERSION,
                          latency_ms=int((time.perf_counter() - start) * 1000))
