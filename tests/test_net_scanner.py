"""Unit tests for net helpers and the read-only scanner."""
from __future__ import annotations

import asyncio

from engine import net
from engine.scanner import Scanner


# --- net ------------------------------------------------------------------
def test_int_to_ip():
    assert net._int_to_ip("1.2.3.4") == "1.2.3.4"
    assert net._int_to_ip(0xC0A80101) == "192.168.1.1"


def test_hosts_excludes_self_and_gateway():
    h = net.hosts("192.168.1.0/29", local_ip="192.168.1.1", gateway_ip="192.168.1.2")
    assert "192.168.1.1" not in h and "192.168.1.2" not in h
    assert "192.168.1.3" in h and "192.168.1.6" in h


def test_vendor_for_offline_and_randomized(monkeypatch):
    monkeypatch.setattr(net, "_oui", {})                  # no OUI DB loaded
    # globally-administered prefix not in the DB -> graceful Unknown
    assert net.vendor_for("00:11:22:33:44:55") == "Unknown"
    # locally-administered (privacy) address -> flagged, not a false vendor
    assert net.vendor_for("4a:15:a2:f8:68:a7") == "Randomized MAC"
    # a known prefix resolves from the dict
    monkeypatch.setattr(net, "_oui", {"001122": "Acme Corp"})
    assert net.vendor_for("00:11:22:aa:bb:cc") == "Acme Corp"


# --- scanner --------------------------------------------------------------
def test_sweep_tracks_first_last_seen_and_offline(ctx, monkeypatch):
    s = Scanner(ctx)
    monkeypatch.setattr(net, "vendor_for", lambda m: "TestCorp")
    monkeypatch.setattr(s, "_sweep_blocking",
                        lambda timeout: {"dd:dd:dd:dd:dd:dd": "192.168.1.50"})
    devs = asyncio.run(s.sweep())
    assert len(devs) == 1
    d = devs[0]
    assert d.ip == "192.168.1.50" and d.vendor == "TestCorp" and d.online is True
    first = d.first_seen

    # next sweep sees nobody -> after the grace window it goes offline, history kept
    monkeypatch.setattr(s, "_sweep_blocking", lambda timeout: {})
    for mac in list(s._last_seen_ts):   # fast-forward past the offline grace
        s._last_seen_ts[mac] -= 999
    devs = asyncio.run(s.sweep())
    assert devs[0].online is False
    assert devs[0].first_seen == first


def test_set_status(ctx, monkeypatch):
    s = Scanner(ctx)
    monkeypatch.setattr(net, "vendor_for", lambda m: "X")
    monkeypatch.setattr(s, "_sweep_blocking",
                        lambda timeout: {"dd:dd:dd:dd:dd:dd": "192.168.1.50"})
    asyncio.run(s.sweep())
    s.set_status("DD:DD:DD:DD:DD:DD", "routed")
    assert s.devices[0].status == "routed"
