import time
import pytest
from service.text_features import TextAnalyzer, normalize
from service.schemas import REASON_CODES

T = TextAnalyzer()


def codes(text):
    return set(T.extract_features(text).codes)


def test_normalize():
    assert normalize("Vérifiez  VOTRE compte!") == "verifiez votre compte!"
    assert normalize("تأكيد حسابك") == "تاكيد حسابك"      # hamza supprimée


def test_contract_example_sentence():
    assert "TEXT_ACCOUNT_VERIFICATION" in codes("Cliquez ici pour vérifier votre compte")


def test_french_phishing_full():
    t = ("URGENT : votre compte sera suspendu dans 24 h. Vérifiez votre compte "
         "et envoyez votre mot de passe.")
    r = T.extract_features(t)
    assert {"TEXT_URGENCY", "TEXT_THREAT", "TEXT_ACCOUNT_VERIFICATION",
            "TEXT_CREDENTIAL_REQUEST"} <= set(r.codes)
    assert r.score >= 0.80


def test_english_phishing():
    c = codes("Your account will be suspended. Please verify your account immediately.")
    assert {"TEXT_THREAT", "TEXT_ACCOUNT_VERIFICATION", "TEXT_URGENCY"} <= c


def test_arabic_phishing():
    c = codes("عاجل: سيتم تعليق حسابك. يرجى تأكيد حسابك وإرسال كلمة المرور")
    assert {"TEXT_URGENCY", "TEXT_THREAT", "TEXT_ACCOUNT_VERIFICATION",
            "TEXT_CREDENTIAL_REQUEST"} <= c


def test_money():
    assert "TEXT_MONEY_REQUEST" in codes("Achète-moi des cartes cadeaux Amazon, c'est pour le CEO")
    assert "TEXT_MONEY_REQUEST" in codes("Effectuez un virement de 5000 dirhams aujourd'hui")


@pytest.mark.parametrize("msg", [
    "Bonjour, on se retrouve à 10h pour la réunion ?",
    "Salut, tu peux relire le compte rendu avant demain ?",
    "J'ai mis à jour les informations du projet sur le drive",
    "Merci pour le virement, bien reçu !",
    "Hi, can you send me the slides when you have a minute?",
    "غدا عندنا اجتماع في الساعة العاشرة",
    "",
])
def test_normal_messages_are_clean(msg):
    assert T.extract_features(msg).reasons == [], msg


def test_urgent_alone_stays_safe():
    r = T.extract_features("Urgent : la réunion est déplacée à 15h")
    assert r.codes == ["TEXT_URGENCY"] and r.score < 0.40


def test_codes_in_closed_list_and_features_numeric():
    r = T.extract_features("URGENT!!! Confirmez votre identité: https://x.com")
    assert all(c in REASON_CODES for c in r.codes)
    assert all(isinstance(v, (int, float)) for v in r.features.values())
    assert r.features["n_exclamations"] == 3 and r.features["n_links_in_text"] == 1


@pytest.mark.parametrize("bad", ["", None, "😀😀😀", "a" * 20000, "ا" * 20000, "verify " * 3000])
def test_robust_and_fast(bad):
    start = time.perf_counter()
    T.extract_features(bad)
    assert time.perf_counter() - start < 0.5
