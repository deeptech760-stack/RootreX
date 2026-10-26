"""Tests for the prerequisite preflight / downloader (no network)."""
from engine import preflight


def test_report_structure():
    r = preflight.report()
    assert set(r) == {"items", "ok", "missing_required"}
    keys = {i["key"] for i in r["items"]}
    assert {"npcap", "admin"} <= keys
    for i in r["items"]:
        assert {"key", "name", "ok", "required", "detail",
                "page", "installer", "silent"} <= set(i)


def test_url_guard():
    assert preflight._official(preflight.NPCAP_INSTALLER)
    assert not preflight._official("https://evil.example/npcap.exe")
    assert not preflight._official("http://npcap.com/x.exe")  # must be https


def test_install_unknown_key():
    assert "error" in preflight.install("bogus")


def test_install_refuses_tampered_url(monkeypatch):
    """Defense in depth: even if a prereq's installer URL were swapped to a
    non-official host, install() must refuse before downloading."""
    bad = preflight.Prereq(
        "npcap", "Npcap", False, True, "",
        "https://npcap.com/#download", "https://evil.example/x.exe", False)
    monkeypatch.setattr(preflight, "check", lambda: [bad])
    r = preflight.install("npcap")
    assert "error" in r and "refusing" in r["error"]
