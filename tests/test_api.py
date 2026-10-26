"""Integration tests for the FastAPI control plane, wired to the real engine
(scanner/jammer/observer/safety) with only network I/O stubbed."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

IP = "192.168.1.50"
MAC = "dd:dd:dd:dd:dd:dd"


@pytest.fixture
def client(ctx, monkeypatch):
    # stub every network touch-point
    monkeypatch.setattr("engine.net.discover", lambda: ctx)
    monkeypatch.setattr("engine.net.vendor_for", lambda m: "TestCorp")
    monkeypatch.setattr("engine.jammer.sendp", lambda p, **k: None)
    monkeypatch.setattr("engine.observer.sendp", lambda p, **k: None)
    monkeypatch.setattr("engine.scanner.Scanner._sweep_blocking",
                        lambda self, timeout: {MAC: IP})

    class DummySniffer:
        def __init__(self, *a, **k): ...
        def start(self): ...
        def stop(self): ...

    monkeypatch.setattr("engine.observer.AsyncSniffer", DummySniffer)

    # silence the perpetual background loops so tests don't leave tasks spinning
    async def _noop():
        return

    monkeypatch.setattr("engine.api._scan_loop", _noop)
    monkeypatch.setattr("engine.api._broadcast_loop", _noop)

    # stub the AP so tests never spawn PowerShell / touch the real Mobile Hotspot
    from engine.ap import APStatus
    from engine.api import state as _state

    class _FakeAP:
        def status(self):
            return APStatus(available=False, state="unavailable", detail="test")
        async def configure(self, *a):
            return self.status()
        async def start(self):
            return self.status()
        async def stop(self):
            return self.status()
        async def refresh(self):
            return self.status()
        def hotspot_iface(self):
            return None

    monkeypatch.setattr(_state, "ap", _FakeAP())

    from engine.api import app
    with TestClient(app) as c:
        yield c


def test_state_shape(client):
    s = client.get("/api/state").json()
    assert s["ok"] is True
    assert s["context"]["gateway_ip"] == "192.168.1.1"
    assert s["consent"] is False
    for key in ("devices", "jamming", "observer", "ap", "allowlist", "log"):
        assert key in s


def test_scan_endpoint_returns_devices(client):
    r = client.post("/api/scan").json()
    assert any(d["ip"] == IP for d in r["devices"])


def test_scan_is_graceful_when_packet_layer_missing(client, monkeypatch):
    # Regression: Rescan must return a clean error, not HTTP 500, when the
    # packet layer is unavailable (e.g. Npcap not installed).
    from engine.api import state

    def boom(timeout):
        raise RuntimeError("winpcap is not installed")

    monkeypatch.setattr(state.scanner, "_sweep_blocking", boom)
    r = client.post("/api/scan")
    assert r.status_code == 200
    assert "error" in r.json()


def test_jam_refused_before_consent(client):
    r = client.post("/api/jam", json={"ip": IP, "mac": MAC, "mode": "cut"}).json()
    assert "error" in r                      # safety gate blocks it, API stays graceful


def test_jam_refused_before_allowlist(client):
    assert client.post("/api/consent", json={"note": "t"}).json()["consent"] is True
    r = client.post("/api/jam", json={"ip": IP, "mac": MAC, "mode": "cut"}).json()
    assert "error" in r                      # consented but not allowlisted


def test_full_consent_allow_route_stop_flow(client):
    assert client.post("/api/consent", json={"note": "lab demo"}).json()["consent"] is True
    assert client.post("/api/allow", json={"ip": IP, "mac": MAC}).json().get("allowed")

    r = client.post("/api/jam", json={"ip": IP, "mac": MAC, "mode": "route"}).json()
    assert r.get("ok") is True and r["mode"] == "route"

    client.post("/api/scan")                 # populate the device table
    s = client.get("/api/state").json()
    assert s["jamming"].get(MAC) == "route"
    # the device table reflects the routed state
    dev = next(d for d in s["devices"] if d["mac"] == MAC)
    assert dev["status"] == "routed"

    # STOP · restore all
    assert client.post("/api/stop_all").json()["ok"] is True
    assert client.get("/api/state").json()["jamming"] == {}


def test_unknown_jam_mode_is_rejected(client):
    client.post("/api/consent", json={"note": "t"})
    client.post("/api/allow", json={"ip": IP, "mac": MAC})
    r = client.post("/api/jam", json={"ip": IP, "mac": MAC, "mode": "nonsense"}).json()
    assert "error" in r


def test_ap_configure_is_graceful_without_hardware(client):
    # winsdk / Mobile Hotspot is almost certainly unavailable in CI — must not crash
    r = client.post("/api/ap/configure",
                    json={"ssid": "RootreX-Lab", "passphrase": "labpass12"}).json()
    assert isinstance(r, dict)
    assert client.get("/api/state").json()["ap"] is not None


def test_consent_revoke(client):
    client.post("/api/consent", json={"note": "t"})
    assert client.post("/api/consent/revoke").json()["consent"] is False
