"""store.py — persistent, per-network device memory.

Names learned on a network (DHCP, mDNS, NetBIOS, UPnP, or the operator's own
hostname) are remembered keyed by MAC, **scoped to the router they were seen on**
(identified by the gateway MAC). So each router keeps its own list of known
devices, and switching networks switches the remembered set — you never see a
friend's floor's devices on your own.

Stored as JSON under %LOCALAPPDATA%\\RootreX\\devices.json:
    { "<gateway-mac>": { "<device-mac>": {name, vendor, first_seen, ...} }, ... }
"""
from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def default_path() -> Path:
    base = Path(os.environ.get("LOCALAPPDATA") or Path.home())
    return base / "RootreX" / "devices.json"


class DeviceStore:
    def __init__(self, path: Optional[Path] = None) -> None:
        self._path = path or default_path()
        self._lock = threading.RLock()
        self._network = "default"
        self._data: dict[str, dict] = {}   # network_id -> {mac -> rec}
        self._load()

    def _load(self) -> None:
        try:
            with open(self._path, encoding="utf-8") as f:
                data = json.load(f)
        except Exception:  # noqa: BLE001
            data = {}
        if not isinstance(data, dict) or not data:
            self._data = {}
            return
        sample = next(iter(data.values()))
        if isinstance(sample, dict) and any(k in sample for k in ("name", "vendor", "last_seen")):
            # migrate old flat {mac: rec} -> one "default" network
            self._data = {"default": {k.lower(): v for k, v in data.items()}}
        else:
            self._data = {
                nid.lower(): {m.lower(): r for m, r in (macs or {}).items()}
                for nid, macs in data.items() if isinstance(macs, dict)
            }

    def _save(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._path.with_suffix(".tmp")
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self._data, f, indent=2, sort_keys=True)
            os.replace(tmp, self._path)
        except Exception:  # noqa: BLE001
            pass

    def set_network(self, nid: str) -> None:
        with self._lock:
            self._network = (nid or "default").lower()

    @property
    def network(self) -> str:
        return self._network

    def _cur(self) -> dict:
        return self._data.setdefault(self._network, {})

    def name(self, mac: str) -> str:
        with self._lock:
            return self._data.get(self._network, {}).get(mac.lower(), {}).get("name", "")

    def get(self, mac: str) -> dict:
        with self._lock:
            return dict(self._data.get(self._network, {}).get(mac.lower(), {}))

    def remember(self, mac: str, name: str = "", vendor: str = "") -> None:
        mac = mac.lower()
        if not name and not vendor:
            return
        with self._lock:
            cur = self._cur()
            rec = cur.get(mac, {})
            changed = False
            if name and rec.get("name") != name:
                rec["name"] = name
                rec["name_seen"] = _now()
                changed = True
            if vendor and rec.get("vendor") != vendor:
                rec["vendor"] = vendor
                changed = True
            if "first_seen" not in rec:
                rec["first_seen"] = _now()
                changed = True
            rec["last_seen"] = _now()
            cur[mac] = rec
            if changed:
                self._save()

    def all(self) -> dict:
        with self._lock:
            return {k: dict(v) for k, v in self._data.get(self._network, {}).items()}

    def networks(self) -> dict:
        with self._lock:
            return {nid: len(macs) for nid, macs in self._data.items()}

    def forget(self, mac: str) -> None:
        with self._lock:
            if self._data.get(self._network, {}).pop(mac.lower(), None) is not None:
                self._save()
