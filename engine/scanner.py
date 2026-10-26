"""scanner.py — read-only live device discovery.

An ARP sweep of the local /24 that never changes remote state. It maintains a
device table with first/last-seen timestamps and a vendor guess, and emits the
live diff so the UI can animate hosts appearing, going quiet, and returning.
"""
from __future__ import annotations

import asyncio
import logging
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from typing import Optional

from scapy.all import ARP, Ether, srp

from . import identify, net, store

log = logging.getLogger("rootrex.scanner")


OFFLINE_GRACE = 20.0  # seconds a device may miss ARP replies before it goes offline


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Device:
    ip: str
    mac: str
    vendor: str
    first_seen: str
    last_seen: str
    online: bool = True
    # UI/engine state, set by jammer/observer, surfaced here for one device table:
    status: str = "live"   # "live" | "cut" | "routed"
    name: str = ""         # resolved hostname (mDNS / NetBIOS / reverse DNS)
    kind: str = "device"   # "self" | "gateway" | "device"

    def as_dict(self) -> dict:
        return asdict(self)


class Scanner:
    def __init__(self, ctx: net.NetContext) -> None:
        self.ctx = ctx
        self._devices: dict[str, Device] = {}  # mac -> Device
        self._last_seen_ts: dict[str, float] = {}  # mac -> epoch of last ARP reply
        self._names = ThreadPoolExecutor(max_workers=8, thread_name_prefix="rx-name")
        self._name_tried: set[str] = set()
        self._hostname = socket.gethostname()
        self._store = store.DeviceStore()   # persistent MAC -> name memory
        self._store.set_network(net.network_id(ctx))

    @property
    def devices(self) -> list[Device]:
        return list(self._devices.values())

    def _sweep_blocking(self, timeout: float) -> dict[str, str]:
        """One synchronous ARP sweep. Returns {mac: ip} for responders."""
        found: dict[str, str] = {}
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.ctx.cidr),
            timeout=timeout, verbose=0, iface=self.ctx.iface,
        )
        for _, rcv in ans:
            found[rcv.hwsrc.lower()] = rcv.psrc
        return found

    async def sweep(self, timeout: float = 2.5) -> list[Device]:
        """Run a sweep off-thread (Scapy is blocking) and merge into the table."""
        try:
            found = await asyncio.to_thread(self._sweep_blocking, timeout)
        except Exception:  # noqa: BLE001
            log.exception("sweep failed (Npcap installed? elevated?)")
            raise
        now = _now()
        now_t = time.time()

        for mac, ip in found.items():
            dev = self._devices.get(mac)
            if dev is None:
                dev = Device(
                    ip=ip, mac=mac, vendor=net.vendor_for(mac),
                    first_seen=now, last_seen=now, online=True,
                    name=self._store.name(mac),   # remembered from a previous run
                )
                self._devices[mac] = dev
            else:
                dev.ip = ip
                dev.last_seen = now
            self._last_seen_ts[mac] = now_t
            self._enrich(dev)

        # Online if seen within the grace window — tolerates a missed sweep or two
        # so a live device (phones answer ARP lazily) doesn't flicker offline.
        for mac, dev in self._devices.items():
            dev.online = (now_t - self._last_seen_ts.get(mac, 0.0)) <= OFFLINE_GRACE

        return self.devices

    def _enrich(self, dev: Device) -> None:
        """Tag this host + gateway, and kick off background name resolution."""
        self._store.remember(dev.mac, dev.name, dev.vendor)  # keep memory fresh
        # Identify ourselves by MAC first — ARP flux during routing can make our
        # own MAC momentarily appear at another IP; never let self become routable.
        if dev.mac == self.ctx.local_mac or dev.ip == self.ctx.local_ip:
            dev.kind = "self"
            dev.ip = self.ctx.local_ip          # pin our IP; ignore spoofed sightings
            if not dev.name:
                dev.name = self._hostname
                self._store.remember(dev.mac, dev.name)
            return
        dev.kind = "gateway" if dev.ip == self.ctx.gateway_ip else "device"
        if not dev.name and dev.mac not in self._name_tried:
            self._name_tried.add(dev.mac)
            self._names.submit(self._resolve, dev.mac, dev.ip)

    def _resolve(self, mac: str, ip: str) -> None:
        try:
            name = identify.resolve_name(ip, self.ctx.local_ip)
        except Exception:  # noqa: BLE001
            name = None
        dev = self._devices.get(mac)
        if dev is not None and name and not dev.name:
            dev.name = name
            self._store.remember(mac, name)

    def remember(self, mac: str, name: str = "", vendor: str = "") -> None:
        """Persist a name learned elsewhere (e.g. the Identify endpoint)."""
        self._store.remember(mac, name, vendor)
        dev = self._devices.get(mac.lower())
        if dev is not None and name and not dev.name:
            dev.name = name

    def reset(self, ctx: net.NetContext) -> None:
        """Switch networks: drop the previous router's device list, load this one's."""
        self.ctx = ctx
        self._devices.clear()
        self._name_tried.clear()
        self._store.set_network(net.network_id(ctx))

    def update_network_key(self) -> None:
        """Re-point the store to the current network id without dropping devices
        (used when the gateway MAC resolves after startup — same network)."""
        self._store.set_network(net.network_id(self.ctx))

    def set_status(self, mac: str, status: str) -> None:
        dev = self._devices.get(mac.lower())
        if dev is not None:
            dev.status = status

    async def run(self, interval: float = 5.0, on_update=None) -> None:
        """Continuous refresh loop. `on_update(devices)` is called each sweep."""
        while True:
            try:
                devices = await self.sweep()
                if on_update is not None:
                    on_update(devices)
            except Exception:  # noqa: BLE001
                log.exception("scanner loop error")
            await asyncio.sleep(interval)
