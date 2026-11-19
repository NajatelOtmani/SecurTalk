import pytest
import requests
import api_ml
from tools import fake_ml_service as svc


def test_extract_urls():
    u = api_ml.extract_urls("Allez sur http://micros0ft-login.com/verify ou bit.ly/abc, merci.")
    assert "http://micros0ft-login.com/verify" in u and "bit.ly/abc" in u
    assert api_ml.extract_urls("Bonjour, ça va ?") == []


def test_faux_service_phishing_et_safe():
    s, label, reasons = svc.score("Votre compte sera suspendu", ["http://micros0ft-login.com/verify"])
    assert label == "Phishing" and s >= 0.8
    assert {r["code"] for r in reasons} >= {"URL_BRAND_IMITATION", "URL_HOMOGLYPH"}
    assert svc.score("Bonjour, réunion à 15h", [])[1] == "Safe"
    assert svc.score("c'est urgent", [])[1] == "Suspicious"
    assert svc.score("lien officiel", ["https://www.microsoft.com/fr-fr"])[1] == "Safe"


def test_analyze_ok(monkeypatch):
    class R:
        def raise_for_status(self): pass
        def json(self): return {"score": 0.9, "label": "Phishing", "reasons": []}
    monkeypatch.setattr(requests, "post", lambda *a, **k: R())
    assert api_ml.analyze("m", "a", "b", "c", "t", [])["label"] == "Phishing"


def test_analyze_timeout_donne_ml_unavailable(monkeypatch):
    def boom(*a, **k):
        raise requests.Timeout()
    monkeypatch.setattr(requests, "post", boom)
    with pytest.raises(api_ml.MlUnavailable):
        api_ml.analyze("m", "a", "b", "c", "t", [])


def test_reponse_invalide(monkeypatch):
    class R:
        def raise_for_status(self): pass
        def json(self): return {"label": "???", "score": 1}
    monkeypatch.setattr(requests, "post", lambda *a, **k: R())
    with pytest.raises(api_ml.MlUnavailable):
        api_ml.analyze("m", "a", "b", "c", "t", [])
