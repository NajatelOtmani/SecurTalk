import ipaddress
import re
from datetime import datetime, timezone

ID_RE = re.compile(r"^[A-Za-z0-9_\-]{1,100}$")


def utcnow():
    """Heure UTC 'naive' (sans fuseau) : c'est ce que SQLite stocke et relit."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def iso(dt):
    """Format ISO 8601 UTC du guide (2.1) : 2026-11-07T10:15:30Z"""
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def make_conversation_id(a, b):
    """conv_<idA>_<idB>, ids tries par ordre alphabetique (guide 2.1)."""
    x, y = sorted([a, b])
    return f"conv_{x}_{y}"


def other_participant(conversation_id, me):
    """Retourne l'autre participant si `me` fait partie de la conversation, sinon None."""
    if not isinstance(conversation_id, str) or not conversation_id.startswith("conv_"):
        return None
    debut = f"conv_{me}_"
    if conversation_id.startswith(debut):
        autre = conversation_id[len(debut):]
        if autre and autre != me and make_conversation_id(me, autre) == conversation_id:
            return autre
    fin = f"_{me}"
    if conversation_id.endswith(fin):
        autre = conversation_id[len("conv_"):-len(fin)]
        if autre and autre != me and make_conversation_id(me, autre) == conversation_id:
            return autre
    return None


def valid_ip(value):
    """Retourne l'IP si valide, sinon 0.0.0.0 (le SOC refuse les IP invalides)."""
    try:
        return str(ipaddress.ip_address(value))
    except (ValueError, TypeError):
        return "0.0.0.0"


def client_ip(request):
    return valid_ip(request.client.host if request.client else None)
