"""FAUX service IA (jalon J3) : répond toujours l'exemple du contrat 2.10.
Sert à débloquer le client et le simulateur du SOC. Port : 8001.
Lancer : cd ml && uvicorn service.main:app --host 127.0.0.1 --port 8001
RÈGLE DE CONFIDENTIALITÉ : on ne journalise ni ne stocke jamais `text`.
"""
import time
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from .config import MODEL_VERSION, MAX_TEXT_CHARS, MAX_URLS, label_from_score
from .schemas import AnalyzeRequest, AnalysisResult, Reason

app = FastAPI(title="SecureTalk AI - Service anti-phishing (MOCK)")


@app.exception_handler(RequestValidationError)
async def bad_format(_: Request, exc: RequestValidationError):
    # Contrat 2.1 : erreur = {"error": "CODE", "message": "..."} avec HTTP 400
    fields = sorted({".".join(str(p) for p in e["loc"][1:]) for e in exc.errors()})
    return JSONResponse(
        status_code=400,
        content={"error": "INVALID_FORMAT",
                 "message": f"Champs invalides ou manquants : {', '.join(fields)}"},
    )


@app.get("/health")
def health():
    return {"status": "ok", "model_version": MODEL_VERSION}


@app.post("/v1/analyze", response_model=AnalysisResult)
def analyze(req: AnalyzeRequest):
    start = time.perf_counter()
    # Robustesse (8.7) : on tronque au lieu de planter ; jamais de 500.
    _text = req.text[:MAX_TEXT_CHARS]   # inutilisé par le mock, utilisé à l'étape 2
    _urls = req.urls[:MAX_URLS]

    score = 0.94  # réponse fixe du contrat 2.10
    result = AnalysisResult(
        message_id=req.message_id,
        score=score,
        label=label_from_score(score),
        reasons=[
            Reason(code="URL_BRAND_IMITATION",
                   text="Le domaine imite Microsoft (micros0ft)"),
            Reason(code="TEXT_URGENCY",
                   text="Message demandant une action immédiate"),
        ],
        model_version=MODEL_VERSION,
        latency_ms=int((time.perf_counter() - start) * 1000),
    )
    # Étape ultérieure : émettre l'événement SOC en tâche de fond (2.10), sans le texte.
    return result
