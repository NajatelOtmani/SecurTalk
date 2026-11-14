import pytest
from service.analyzer import PhishingDetector
from service.model import MLModel, load_if_available
from training.build_dataset import build_rows
from training.train_baseline import fit_model

ROWS = build_rows(seed=3, per_template=6)


@pytest.fixture(scope="module")
def model():
    return fit_model(ROWS, n_trees=40)


def test_predict_in_range(model):
    for t in ["Bonjour, réunion à 10h ?", "Vérifiez votre compte http://micros0ft-login.com"]:
        d = PhishingDetector().analyze(t, [])
        assert 0.0 <= model.predict(t, d.features) <= 1.0


def test_save_and_load_roundtrip(model, tmp_path):
    p = tmp_path / "m.joblib"
    model.save(p)
    loaded = MLModel.load(p)
    d = PhishingDetector().analyze("test", [])
    assert loaded.predict("test", d.features) == pytest.approx(model.predict("test", d.features))
    assert loaded.version == model.version


def test_missing_or_corrupt_file_gives_none(tmp_path):
    assert load_if_available(tmp_path / "absent.joblib") is None
    bad = tmp_path / "bad.joblib"
    bad.write_bytes(b"not a model")
    assert load_if_available(bad) is None


def test_detector_with_model_never_lowers_rule_score(model):
    text, urls = "Vérifiez votre compte immédiatement", ["http://micros0ft-login.com/verify"]
    base = PhishingDetector().analyze(text, urls).score
    assert PhishingDetector(model=model).analyze(text, urls).score >= base
