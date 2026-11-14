import pytest
from service import soc_client


@pytest.fixture(autouse=True)
def isolated_soc(tmp_path, monkeypatch):
    """Les tests n'écrivent jamais dans ml/ et ne contactent jamais un vrai SOC."""
    monkeypatch.setattr(soc_client, "LOCAL_PATH", tmp_path / "events.jsonl")
    monkeypatch.setattr(soc_client, "PENDING_PATH", tmp_path / "events_pending.jsonl")
    monkeypatch.setenv("SOC_KEY_PHISHING", "")
