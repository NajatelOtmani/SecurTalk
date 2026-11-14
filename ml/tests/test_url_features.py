import pytest
from service.url_features import UrlAnalyzer, levenshtein
from service.schemas import REASON_CODES

A = UrlAnalyzer()


def codes(url):
    return set(A.check_domain(url).codes)


def test_levenshtein():
    assert levenshtein("google", "googie") == 1
    assert levenshtein("abc", "abc") == 0


def test_contract_example_brand_and_homoglyph():
    c = codes("http://micros0ft-login.com/verify")
    assert {"URL_BRAND_IMITATION", "URL_HOMOGLYPH"} <= c
    assert A.check_domain("http://micros0ft-login.com/verify").score >= 0.80   # => Phishing


def test_without_scheme():
    assert "URL_BRAND_IMITATION" in codes("micros0ft-login.com/verify")


def test_paypal_digit_one():
    assert "URL_BRAND_IMITATION" in codes("https://paypa1.com/login")


def test_cyrillic_homoglyph():
    assert {"URL_HOMOGLYPH", "URL_BRAND_IMITATION"} <= codes("https://microsоft.com")  # 'о' cyrillique


def test_brand_in_subdomain_of_other_domain():
    assert "URL_BRAND_IMITATION" in codes("https://microsoft.com.evil-site.xyz/login")


@pytest.mark.parametrize("url", [
    "https://www.microsoft.com", "https://login.microsoft.com/x", "https://paypal.com",
    "https://mail.google.com", "https://github.com", "https://www.ensa.ac.ma",
    "https://web3.com", "https://pineapple.com", "https://applepie.com",
])
def test_legit_links_are_clean(url):
    assert codes(url) == set(), url


def test_ip_address():
    assert codes("http://192.168.1.5/login") == {"URL_IP_ADDRESS"}


def test_shortener_and_tld():
    assert "URL_SHORTENER" in codes("https://bit.ly/3abc")
    assert "URL_SUSPICIOUS_TLD" in codes("http://free-gift.top")


def test_too_long():
    assert "URL_TOO_LONG" in codes("http://a.b.c.d.example.com/" + "x" * 80)


@pytest.mark.parametrize("bad", ["", "   ", "http://", "://", "http://[::1", "😀", "a" * 5000])
def test_never_crashes(bad):
    r = A.check_domain(bad)
    assert isinstance(r.reasons, list)


def test_analyze_aggregates_and_codes_are_in_closed_list():
    res = A.analyze(["http://micros0ft-login.com/verify", "https://bit.ly/x", "https://github.com"])
    assert res.score >= 0.80
    assert all(code in REASON_CODES for code, _ in res.reasons)
    assert len({c for c, _ in res.reasons}) == len(res.reasons)   # pas de doublon
    assert A.analyze([]).score == 0.0


def test_features_are_numeric():
    f = A.check_domain("http://micros0ft-login.com/verify").features
    assert all(isinstance(v, (int, float)) for v in f.values())
    assert f["n_digits_in_domain"] == 1 and f["brand_imitation"] == 1
