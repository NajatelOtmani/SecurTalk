"""Le contrat 2.10 transformé en code Pydantic (requête + réponse)."""
from typing import List, Literal
from pydantic import BaseModel, Field

# Liste fermée des codes de raison (guide 8.2). Ajouter un code ici ET dans le guide.
REASON_CODES = {
    "URL_BRAND_IMITATION", "URL_HOMOGLYPH", "URL_SUSPICIOUS_TLD",
    "URL_IP_ADDRESS", "URL_SHORTENER", "URL_TOO_LONG",
    "TEXT_URGENCY", "TEXT_ACCOUNT_VERIFICATION", "TEXT_THREAT",
    "TEXT_CREDENTIAL_REQUEST", "TEXT_MONEY_REQUEST", "MODEL_HIGH_SCORE",
}


class AnalyzeRequest(BaseModel):
    message_id: str
    sender_id: str
    receiver_id: str
    conversation_id: str
    text: str = ""
    urls: List[str] = Field(default_factory=list)


class Reason(BaseModel):
    code: str
    text: str


class AnalysisResult(BaseModel):
    message_id: str
    score: float = Field(ge=0.0, le=1.0)
    label: Literal["Safe", "Suspicious", "Phishing"]
    reasons: List[Reason]
    model_version: str
    latency_ms: int
