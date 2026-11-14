"""Tables SQLite (guide 4.1). Le backend ne stocke JAMAIS de texte en clair ni de cle en clair."""
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from app.utils import utcnow


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    username: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(16), default="active")      # active | locked
    public_key_pem: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Session(Base):
    __tablename__ = "sessions"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)  # SHA-256 du jeton
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    ip: Mapped[str] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime)


class Conversation(Base):
    __tablename__ = "conversations"
    conversation_id: Mapped[str] = mapped_column(String(210), primary_key=True)
    user_a: Mapped[str] = mapped_column(String(100), index=True)
    user_b: Mapped[str] = mapped_column(String(100), index=True)
    rotation_required: Mapped[bool] = mapped_column(Boolean, default=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class KeyExchange(Base):
    """Cle de session enveloppee en RSA-OAEP : le backend ne peut pas l'ouvrir."""
    __tablename__ = "key_exchanges"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    conversation_id: Mapped[str] = mapped_column(String(210), index=True)
    from_user_id: Mapped[str] = mapped_column(String(100))
    to_user_id: Mapped[str] = mapped_column(String(100), index=True)
    key_id: Mapped[str] = mapped_column(String(100))
    wrapped_key_b64: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    delivered_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)


class PendingMessage(Base):
    """File 'a livrer'. packet_json = le paquet chiffre (jamais lu, jamais journalise)."""
    __tablename__ = "messages"
    message_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    conversation_id: Mapped[str] = mapped_column(String(210))
    sender_id: Mapped[str] = mapped_column(String(100))
    receiver_id: Mapped[str] = mapped_column(String(100))
    packet_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    delivered_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    acked_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    __table_args__ = (Index("ix_messages_receiver_delivered", "receiver_id", "delivered_at"),)


class AuditLog(Base):
    """Journal des commandes internes (qui / quoi / quand). On ne l'efface jamais."""
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    actor: Mapped[str] = mapped_column(String(100))
    action: Mapped[str] = mapped_column(String(100))
    object: Mapped[str] = mapped_column(String(210))
    details_json: Mapped[str] = mapped_column(Text, default="{}")
