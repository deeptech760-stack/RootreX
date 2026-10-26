"""Unit/integration tests for the ARP jammer against a real SafetyManager.
`sendp` is stubbed so no frames leave the machine; we assert on what *would*
be sent and on the safety bookkeeping."""
from __future__ import annotations

import asyncio

import pytest
from scapy.all import ARP

from engine.jammer import Jammer
from engine.safety import ConsentError, SafetyManager

IP = "192.168.1.50"
MAC = "dd:dd:dd:dd:dd:dd"


def test_cut_registers_poison_and_restore_puts_truth_back(ctx, monkeypatch):
    sent = []
    monkeypatch.setattr("engine.jammer.sendp", lambda p, **k: sent.append(p))
    sm = SafetyManager()
    j = Jammer(ctx, sm)
    sm.grant_consent("lab")
    sm.allow(IP, MAC)

    async def scenario():
        await j.cut(IP, MAC)
        assert j.active.get(MAC) == "cut"
        assert any(ARP in p and p[ARP].op == 2 for p in sent), "poison ARP should be sent"
        sent.clear()
        await j.stop(MAC)
        assert j.active == {}

    asyncio.run(scenario())
    # the restore burst must advertise the REAL gateway mac back to the target
    assert any(ARP in p and p[ARP].hwsrc == "bb:bb:bb:bb:bb:bb" for p in sent)


def test_route_poisons_both_directions(ctx, monkeypatch):
    sent = []
    monkeypatch.setattr("engine.jammer.sendp", lambda p, **k: sent.append(p))
    sm = SafetyManager()
    j = Jammer(ctx, sm)
    sm.grant_consent()
    sm.allow(IP, MAC)

    async def scenario():
        await j.route(IP, MAC)
        assert j.active.get(MAC) == "route"
        await j.stop_all()

    asyncio.run(scenario())
    # route mode claims the gateway IP to the target AND the target IP to the gateway
    psrcs = {p[ARP].psrc for p in sent if ARP in p}
    assert "192.168.1.1" in psrcs and "192.168.1.50" in psrcs


def test_jam_refused_without_allowlist(ctx, monkeypatch):
    monkeypatch.setattr("engine.jammer.sendp", lambda p, **k: None)
    sm = SafetyManager()
    j = Jammer(ctx, sm)
    sm.grant_consent()                      # consented, but target NOT allowlisted

    async def scenario():
        with pytest.raises(ConsentError):
            await j.cut(IP, MAC)

    asyncio.run(scenario())
    assert j.active == {}


def test_build_record_fails_without_gateway_mac(monkeypatch):
    from engine.net import NetContext
    monkeypatch.setattr("engine.jammer.sendp", lambda p, **k: None)
    ctx = NetContext("i", "192.168.1.10", "aa:aa:aa:aa:aa:aa", "192.168.1.1", None, "192.168.1.0/24")
    sm = SafetyManager()
    j = Jammer(ctx, sm)
    sm.grant_consent()
    sm.allow(IP, MAC)

    async def scenario():
        with pytest.raises(RuntimeError):
            await j.cut(IP, MAC)

    asyncio.run(scenario())
