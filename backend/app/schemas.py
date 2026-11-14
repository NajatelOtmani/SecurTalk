"""Contrats d'entree (Pydantic). Le paquet Message est celui du guide 2.6."""
import base64
import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator

ID_PATTERN = r"^[A-Za-z0-9_\-]{1,100}$"


def _b64_strict(v, champ):
    try:
        base64.b64decode(v.encode("ascii"), validate=True)
    except Exception:
        raise ValueError(f"{champ} : base64 invalide") from None
    return v


class RegisterIn(BaseModel):
    username: str = Field(max_length=256)
    password: str = Field(max_length=256)
    public_key_pem: str = Field(max_length=4096)


class LoginIn(BaseModel):
    username: str = Field(max_length=256)
    password: str = Field(max_length=256)


class MessagePacket(BaseModel):
    """Contrat 2.6. Le backend ne lit jamais ciphertext_b64 : il en verifie seulement le format."""
    model_config = ConfigDict(extra="forbid")
    message_id: str
    conversation_id: str = Field(pattern=ID_PATTERN)
    sender_id: str = Field(pattern=ID_PATTERN)
    receiver_id: str = Field(pattern=ID_PATTERN)
    mode: Literal["GCM", "CMAC"]
    key_id: str = Field(pattern=ID_PATTERN)
    counter: StrictInt = Field(ge=1, le=2**53)
    nonce_b64: str = Field(min_length=1, max_length=128)
    ciphertext_b64: str = Field(max_length=90000)
    tag_b64: str = Field(min_length=1, max_length=128)
    timestamp: str

    @field_validator("message_id")
    @classmethod
    def _uuid(cls, v):
        try:
            return str(uuid.UUID(v))
        except Exception:
            raise ValueError("message_id : UUID invalide") from None

    @field_validator("nonce_b64", "ciphertext_b64", "tag_b64")
    @classmethod
    def _b64(cls, v, info):
        return _b64_strict(v, info.field_name)

    @field_validator("timestamp")
    @classmethod
    def _ts(cls, v):
        try:
            datetime.fromisoformat(v)
        except Exception:
            raise ValueError("timestamp : date ISO 8601 invalide") from None
        return v


class KeyExchangeIn(BaseModel):
    conversation_id: str = Field(pattern=ID_PATTERN)
    to_user_id: str = Field(pattern=ID_PATTERN)
    key_id: str = Field(pattern=ID_PATTERN)
    wrapped_key_b64: str = Field(min_length=1, max_length=4096)

    @field_validator("wrapped_key_b64")
    @classmethod
    def _b64(cls, v):
        return _b64_strict(v, "wrapped_key_b64")
