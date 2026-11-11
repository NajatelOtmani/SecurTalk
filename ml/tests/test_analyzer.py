import pytest
from fastapi.testclient import TestClient
from service import main
from service.analyzer import PhishingDetector, extract_urls
from service.schemas import REASON_CODES

D = PhishingDetector()


def test_extract_urls():
    assert extract_urls("Va sur http://a.com/x, puis www.b.org.") == ["http://a.com/x", "www.b.org"]
    assert extract_urls("rien ici") == []


def test_normal_message_is_safe():
    r = D.analyze("Salut, la réunion est à 10h, tu peux envoyer les slides ?", [])
    assert r.label == "Safe" and r.score < 0.40 and r.reasons == []


def test_legit_company_link_is_safe():
    r = D.analyze("Voici le lien de la doc : https://learn.microsoft.com/fr-fr/", [])
    assert r.label == "Safe"


def test_brand_link_alone_is_phishing():
    assert D.analyze("regarde ça", ["http://micros0ft-login.com/verify"]).label == "Phishing"


def test_text_only_phishing():
    r = D.analyze("URGENT : votre compte sera suspendu. Vérifiez votre compte et envoyez "
                  "votre mot de passe.", [])
    assert r.label == "Phishing"


def test_suspicious_middle_zone():
    r = D.analyze("Voir ça", ["https://bit.ly/3abc"])
    assert r.label == "Suspicious" and 0.40 <= r.score < 0.80


def test_link_only_in_text_is_still_found():
    r = D.analyze("Cliquez : http://micros0ft-login.com/verify", [])   # le client a oublié `urls`
    assert "URL_BRAND_IMITATION" in r.reason_codes and r.url_domains


def test_score_range_and_codes():
    r = D.analyze("URGENT!!! vérifiez votre compte, envoyez votre mot de passe, virement",
                  ["http://192.168.0.1/x", "https://paypa1.top"])
    assert 0.0 <= r.score <= 1.0 and set(r.reason_codes) <= REASON_CODES


def test_model_hook():
    class Fake:
        def predict(self, f): return 0.95
    r = PhishingDetector(model=Fake()).analyze("bonjour", [])
    assert r.label == "Phishing" and "MODEL_HIGH_SCORE" in r.reason_codes


def test_features_have_stable_keys():
    a = D.analyze("bonjour", []).features
    b = D.analyze("x", ["http://micros0ft-login.com"]).features
    assert set(a) == set(b)


def test_endpoint_never_500_and_never_logs_text(monkeypatch, caplog):
    client = TestClient(main.app)
    body = {"message_id": "m1", "sender_id": "u_1a", "receiver_id": "u_2b",
            "conversation_id": "conv_u_1a_u_2b", "text": "MOT-SECRET-XYZ", "urls": []}
    with caplog.at_level("DEBUG"):
        assert client.post("/v1/analyze", json=body).status_code == 200
        monkeypatch.setattr(main.detector, "analyze", lambda *a: 1 / 0)
        r = client.post("/v1/analyze", json=body)
    assert r.status_code == 200 and r.json()["label"] == "Suspicious"
    assert "MOT-SECRET-XYZ" not in caplog.text
