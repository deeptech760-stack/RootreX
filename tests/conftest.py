"""Shared fixtures. Network I/O is stubbed everywhere — no Npcap, no admin,
no packets leave the machine. The real engine logic runs for real."""
from __future__ import annotations

import os
import sys

import pytest

# Make the repo root importable (so `import engine` works under `python -m pytest`).
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.net import NetContext  # noqa: E402
from engine.safety import safety as global_safety  # noqa: E402


@pytest.fixture
def ctx() -> NetContext:
    return NetContext(
        iface="TestIface",
        local_ip="192.168.1.10",
        local_mac="aa:aa:aa:aa:aa:aa",
        gateway_ip="192.168.1.1",
        gateway_mac="bb:bb:bb:bb:bb:bb",
        cidr="192.168.1.0/24",
    )


@pytest.fixture(autouse=True)
def _isolate_store(tmp_path, monkeypatch):
    """Keep tests from reading/writing the real device-memory file."""
    monkeypatch.setattr("engine.store.default_path", lambda: tmp_path / "devices.json")


@pytest.fixture(autouse=True)
def reset_global_safety():
    """The API uses a process-wide SafetyManager; reset it between tests."""
    for mgr in (global_safety,):
        mgr._consent = False
        mgr._consent_note = ""
        mgr._allow.clear()
        mgr._poisons.clear()
        mgr._log.clear()
    yield
    global_safety._poisons.clear()
