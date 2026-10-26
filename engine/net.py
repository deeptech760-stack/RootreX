"""net.py — interface / gateway discovery and vendor lookup.

Read-only helpers that the rest of the engine builds on. Nothing here changes
remote state. IP forwarding for route-through is done in userspace by the
observer/jammer (sniff + re-send), deliberately avoiding a registry change that
would need a reboot and would be harder to cleanly undo.
"""
from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, asdict
from typing import Optional

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # hush import noise

from scapy.all import ARP, Ether, conf, get_if_hwaddr, srp  # noqa: E402

log = logging.getLogger("rootrex.net")


@dataclass
class NetContext:
    iface: str
    local_ip: str
    local_mac: str
    gateway_ip: str
    gateway_mac: Optional[str]
    cidr: str

    def as_dict(self) -> dict:
        return asdict(self)


def _default_route() -> tuple[str, str, str]:
    """Return (iface, local_ip, gateway_ip) for the default route."""
    iface, local_ip, gw_ip = conf.route.route("0.0.0.0")
    return str(iface), str(local_ip), str(gw_ip)


def _netmask_for(local_ip: str) -> str:
    """Best-effort netmask from Scapy's routing table; default /24."""
    best = None
    for net, msk, gw, iface, outip, metric in conf.route.routes:
        try:
            network = ipaddress.ip_network(
                f"{_int_to_ip(net)}/{_int_to_ip(msk)}", strict=False)
        except Exception:  # noqa: BLE001
            continue
        if ipaddress.ip_address(local_ip) in network and network.prefixlen not in (0, 32):
            if best is None or network.prefixlen > best.prefixlen:
                best = network
    if best is not None:
        return str(best.netmask)
    return "255.255.255.0"


def _int_to_ip(value) -> str:
    if isinstance(value, str):
        return value
    return str(ipaddress.ip_address(int(value) & 0xFFFFFFFF))


def resolve_mac(ip: str, timeout: float = 2.0, retry: int = 2) -> Optional[str]:
    """ARP who-has: ask the network for the MAC behind an IP (read-only)."""
    try:
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
            timeout=timeout, retry=retry, verbose=0,
        )
    except Exception:  # noqa: BLE001
        log.exception("resolve_mac failed for %s", ip)
        return None
    for _, rcv in ans:
        return rcv.hwsrc.lower()
    return None


def discover() -> NetContext:
    """Discover the active interface, our address, and the gateway."""
    iface, local_ip, gw_ip = _default_route()
    try:
        local_mac = get_if_hwaddr(iface).lower()
    except Exception:  # noqa: BLE001
        local_mac = get_if_hwaddr(conf.iface).lower()
        iface = str(conf.iface)
    netmask = _netmask_for(local_ip)
    cidr = str(ipaddress.ip_network(f"{local_ip}/{netmask}", strict=False))
    gw_mac = resolve_mac(gw_ip)
    ctx = NetContext(
        iface=iface, local_ip=local_ip, local_mac=local_mac,
        gateway_ip=gw_ip, gateway_mac=gw_mac, cidr=cidr,
    )
    log.info("discovered %s", ctx)
    return ctx


def network_id(ctx: "NetContext") -> str:
    """A stable identity for the network we're on — the router's MAC when known
    (unique per router, even if two routers share 192.168.1.x), else its IP."""
    return (ctx.gateway_mac or ctx.gateway_ip or "unknown").lower()


def hosts(cidr: str, local_ip: str, gateway_ip: str) -> list[str]:
    """Enumerate candidate host IPs in the subnet, excluding us and the gateway."""
    net = ipaddress.ip_network(cidr, strict=False)
    skip = {local_ip, gateway_ip}
    return [str(h) for h in net.hosts() if str(h) not in skip]


# --- vendor lookup (offline OUI DB) ---------------------------------------
# We parse mac_vendor_lookup's cached OUI file into a dict and look up prefixes
# ourselves. The library's own .lookup() lazily downloads the DB via asyncio on
# first use, which fails when first called from a capture worker thread under a
# running event loop — a plain dict read is thread-safe and has no such pitfall.
_oui: Optional[dict] = None


def prime_vendors() -> None:
    """Ensure the OUI database is downloaded + loaded. Call once from the main
    thread (no running event loop) so the download, if needed, can run."""
    global _oui
    try:
        import os
        from mac_vendor_lookup import BaseMacLookup, MacLookup
        path = BaseMacLookup.cache_path
        if not os.path.exists(path):
            try:
                MacLookup().update_vendors()  # sync download to cache
            except Exception:  # noqa: BLE001
                import asyncio
                from mac_vendor_lookup import AsyncMacLookup
                asyncio.run(AsyncMacLookup().update_vendors())
    except Exception:  # noqa: BLE001
        pass
    _load_oui()


def _load_oui() -> None:
    global _oui
    _oui = {}
    try:
        from mac_vendor_lookup import BaseMacLookup
        with open(BaseMacLookup.cache_path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                prefix, sep, vendor = line.partition(":")
                if sep and vendor.strip():
                    _oui[prefix.strip().upper()] = vendor.strip()
    except Exception:  # noqa: BLE001
        _oui = {}


def vendor_for(mac: str) -> str:
    """Best-effort MAC -> vendor from the local OUI DB (thread-safe dict read)."""
    global _oui
    if _oui is None:
        _load_oui()
    hexmac = mac.upper().replace(":", "").replace("-", "")
    try:
        if len(hexmac) >= 2 and int(hexmac[:2], 16) & 0x02:
            return "Randomized MAC"   # locally-administered (privacy) address
    except ValueError:
        pass
    return (_oui or {}).get(hexmac[:6], "Unknown")
