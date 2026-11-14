"""Appel au service IA anti-phishing (contrat 2.10). Aucune interface ici."""
import re
import requests
import config


class MlUnavailable(Exception):
    pass


URL_RE = re.compile(
    r"https?://[^\s<>\"']+|(?:www\.)?(?:[a-z0-9-]+\.)+(?:com|net|org|fr|ma|io|info|xyz|top|ru|tk|co|app|dev|biz|ly)"
    r"(?:/[^\s<>\"']*)?", re.I)


def extract_urls(text):
    """Liens avec http(s) ET domaines sans http (guide 7.2). On n'ouvre jamais un lien."""
    urls = []
    for m in URL_RE.finditer(text):
        u = m.group(0).rstrip(".,;:!?)")
        if u not in urls:
            urls.append(u)
    return urls[:20]


def analyze(message_id, sender_id, receiver_id, conversation_id, text, urls):
    try:
        r = requests.post(config.ML_URL + "/v1/analyze", timeout=config.ML_TIMEOUT,
                          headers={"X-Contract-Version": config.CONTRACT_VERSION},
                          json={"message_id": message_id, "sender_id": sender_id, "receiver_id": receiver_id,
                                "conversation_id": conversation_id, "text": text, "urls": urls})
        r.raise_for_status()
        d = r.json()
        if d.get("label") not in ("Safe", "Suspicious", "Phishing"):
            raise ValueError("label inconnu")
        float(d["score"])
        return d
    except (requests.RequestException, ValueError, KeyError, TypeError):
        raise MlUnavailable()


def health():
    try:
        r = requests.get(config.ML_URL + "/health", timeout=config.ML_TIMEOUT)
        r.raise_for_status()
        return r.json()
    except (requests.RequestException, ValueError):
        raise MlUnavailable()
