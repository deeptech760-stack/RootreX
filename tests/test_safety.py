"""Unit tests for the safety core — the load-bearing consent/allowlist/restore layer."""
from __future__ import annotations

import pytest

from engine.safety import ConsentError, PoisonRecord, SafetyManager

MAC = "cc:cc:cc:cc:cc:cc"
IP = "192.168.1.50"


def _rec(mode="cut") -> PoisonRecord:
    return PoisonRecord(target_ip=IP, target_mac=MAC, gateway_ip="192.168.1.1",
                        gateway_mac="bb:bb:bb:bb:bb:bb", mode=mode)


def test_allow_requires_consent():
    sm = SafetyManager()
    with pytest.raises(ConsentError):
        sm.allow(IP, MAC)


def test_allowlist_is_case_insensitive():
    sm = SafetyManager()
    sm.grant_consent("lab")
    sm.allow(IP, "CC:CC:CC:CC:CC:CC")
    assert sm.is_allowed(MAC)
    sm.require_allowed(MAC)  # must not raise


def test_poison_requires_consent_then_allow_then_restore_fn():
    sm = SafetyManager()
    r = _rec()
    with pytest.raises(ConsentError):           # no consent
        sm.register_poison(r)
    sm.grant_consent()
    with pytest.raises(ConsentError):           # consented but not allowlisted
        sm.register_poison(r)
    sm.allow(IP, MAC)
    with pytest.raises(ConsentError):           # allowlisted but no restore fn
        sm.register_poison(r)
    calls: list[PoisonRecord] = []
    sm.set_restore_fn(calls.append)
    sm.register_poison(r)
    assert len(sm.active_poisons) == 1


def test_restore_all_runs_restore_burst_and_clears():
    sm = SafetyManager()
    sm.grant_consent()
    sm.allow(IP, MAC)
    calls: list[PoisonRecord] = []
    sm.set_restore_fn(calls.append)
    sm.register_poison(_rec())
    sm.restore_all()
    assert sm.active_poisons == []
    assert len(calls) == 5          # _safe_restore sends the correct ARP 5x for reliability


def test_restore_all_swallows_restore_errors():
    sm = SafetyManager()
    sm.grant_consent()
    sm.allow(IP, MAC)

    def boom(_rec):
        raise RuntimeError("wire down")

    sm.set_restore_fn(boom)
    sm.register_poison(_rec())
    sm.restore_all()                # must not raise even though restore throws
    assert sm.active_poisons == []


def test_disallow_restores_if_currently_poisoned():
    sm = SafetyManager()
    sm.grant_consent()
    sm.allow(IP, MAC)
    restored: list[PoisonRecord] = []
    sm.set_restore_fn(restored.append)
    sm.register_poison(_rec())
    sm.disallow(MAC)
    assert sm.active_poisons == []
    assert not sm.is_allowed(MAC)
    assert restored, "disallowing a poisoned target must restore it first"


def test_revoke_consent_restores_everything():
    sm = SafetyManager()
    sm.grant_consent()
    sm.allow(IP, MAC)
    sm.set_restore_fn(lambda r: None)
    sm.register_poison(_rec())
    sm.revoke_consent()
    assert sm.active_poisons == []
    assert sm.has_consent is False


def test_session_log_records_actions():
    sm = SafetyManager()
    sm.grant_consent("demo")
    sm.allow(IP, MAC)
    actions = [e["action"] for e in sm.session_log]
    assert "consent.granted" in actions and "allowlist.add" in actions
