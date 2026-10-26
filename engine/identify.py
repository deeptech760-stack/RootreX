"""identify.py — best-effort device name resolution.

A MAC alone isn't actionable ("which one is my phone?"), so we enrich each host
with a friendly name using standard, non-intrusive discovery queries — the same
ones Fing/netcut use. None of this touches the device beyond a normal name query:

  * mDNS / Bonjour (UDP 5353) — reverse PTR; great for phones, TVs, printers.
  * NetBIOS node status (nbtstat) — Windows PC names.
  * reverse DNS (PTR via the local resolver) — router-registered names.

Returns the first useful name, or None. Each resolver is time-boxed and never
raises to the caller.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import subprocess
import time
from typing import Optional


def _looks_useful(name: Optional[str]) -> Optional[str]:
    if not name:
        return None
    name = name.strip().rstrip(".")
    if not name or name.replace(".", "").replace("-", "").isdigit():
        return None  # e.g. a bare IP
    return name


def reverse_dns(ip: str, timeout: float = 1.0) -> Optional[str]:
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        host = socket.gethostbyaddr(ip)[0]
        return _looks_useful(host.split(".")[0])
    except Exception:  # noqa: BLE001
        return None
    finally:
        socket.setdefaulttimeout(old)


def netbios_name(ip: str, timeout: float = 2.5) -> Optional[str]:
    try:
        out = subprocess.run(
            ["nbtstat", "-A", ip], capture_output=True, text=True,
            timeout=timeout, creationflags=0x08000000,  # CREATE_NO_WINDOW
        ).stdout
    except Exception:  # noqa: BLE001
        return None
    for line in out.splitlines():
        m = re.match(r"\s*([^\s<]+)\s+<00>\s+UNIQUE", line)
        if m:
            return _looks_useful(m.group(1))
    return None


def mdns_name(ip: str, local_ip: str = "0.0.0.0", timeout: float = 1.2) -> Optional[str]:
    """Reverse mDNS PTR query (QU unicast response) for an IP's .local name."""
    try:
        from scapy.all import DNS, DNSQR
    except Exception:  # noqa: BLE001
        return None
    rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    query = DNS(rd=0, qd=DNSQR(qname=rev, qtype="PTR", qclass=0x8001))  # QU bit
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((local_ip, 0))
        except Exception:  # noqa: BLE001
            pass
        sock.settimeout(timeout)
        sock.sendto(bytes(query), ("224.0.0.251", 5353))
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data = sock.recvfrom(4096)[0]
            except socket.timeout:
                break
            try:
                resp = DNS(data)
            except Exception:  # noqa: BLE001
                continue
            for i in range(resp.ancount or 0):
                try:
                    rr = resp.an[i]
                except Exception:  # noqa: BLE001
                    break
                if getattr(rr, "type", None) == 12:  # PTR
                    rd = rr.rdata
                    name = rd.decode(errors="ignore") if isinstance(rd, bytes) else str(rd)
                    name = name.rstrip(".")
                    if name.endswith(".local"):
                        name = name[:-6]
                    useful = _looks_useful(name)
                    if useful:
                        return useful
        return None
    except Exception:  # noqa: BLE001
        return None
    finally:
        sock.close()


def ssdp_discover(local_ip: str = "0.0.0.0", timeout: float = 3.0) -> dict:
    """Active UPnP/SSDP probe (one multicast M-SEARCH, no routing). Returns
    {ip: friendly_name}. Great for TVs, media boxes, routers and many IoT."""
    import re as _re
    import urllib.request

    msg = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 2\r\n"
        "ST: ssdp:all\r\n\r\n"
    ).encode()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    locations: dict[str, str] = {}
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((local_ip, 0))
        except Exception:  # noqa: BLE001
            pass
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.settimeout(timeout)
        sock.sendto(msg, ("239.255.255.250", 1900))
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                break
            m = _re.search(r"(?im)^LOCATION:\s*(.+)$", data.decode(errors="ignore"))
            if m:
                locations.setdefault(addr[0], m.group(1).strip())
    except Exception:  # noqa: BLE001
        pass
    finally:
        sock.close()

    names: dict[str, str] = {}
    for ip, loc in locations.items():
        try:
            xml = urllib.request.urlopen(loc, timeout=2).read().decode(errors="ignore")
            fn = _re.search(r"<friendlyName>(.*?)</friendlyName>", xml, _re.S)
            mdl = _re.search(r"<modelName>(.*?)</modelName>", xml, _re.S)
            name = (fn.group(1).strip() if fn else "") or (mdl.group(1).strip() if mdl else "")
            names[ip] = _looks_useful(name) or "UPnP device"
        except Exception:  # noqa: BLE001
            names.setdefault(ip, "UPnP device")
    return names


def dhcp_passive(iface: str, duration: float = 25.0) -> dict:
    """Passively sniff DHCP (UDP 67/68) for a window — no routing, no injection.
    Devices announce their hostname (option 12) on join/renew. Returns
    {mac: {"name", "vendor_class", "ip"}}."""
    try:
        from scapy.all import DHCP, Ether, sniff
    except Exception:  # noqa: BLE001
        return {}
    found: dict[str, dict] = {}

    def handle(pkt) -> None:
        if DHCP not in pkt:
            return
        mac = pkt[Ether].src.lower() if Ether in pkt else None
        host = vclass = reqip = ""
        for opt in pkt[DHCP].options:
            if not isinstance(opt, tuple):
                continue
            key, val = opt[0], (opt[1] if len(opt) > 1 else b"")
            dec = val.decode(errors="ignore") if isinstance(val, bytes) else str(val)
            if key == "hostname":
                host = dec
            elif key == "vendor_class_id":
                vclass = dec
            elif key == "requested_addr":
                reqip = dec
        if mac and (host or vclass):
            found[mac] = {"name": host, "vendor_class": vclass, "ip": reqip}

    try:
        sniff(iface=iface, filter="udp and (port 67 or port 68)",
              prn=handle, timeout=duration, store=False)
    except Exception:  # noqa: BLE001
        pass
    return found


_ORG_HINTS = [
    ("fbcdn", "Meta / Instagram"), ("instagram", "Instagram"), ("facebook", "Meta"),
    ("whatsapp", "WhatsApp"), ("googlevideo", "YouTube"), ("youtube", "YouTube"),
    ("1e100.net", "Google"), ("gstatic", "Google"), ("ggpht", "Google"),
    ("google", "Google"), ("cloudfront", "Amazon CloudFront"), ("amazonaws", "Amazon AWS"),
    ("amazon", "Amazon"), ("akamai", "Akamai"), ("fastly", "Fastly"),
    ("cloudflare", "Cloudflare"), ("icloud", "Apple"), ("apple", "Apple"),
    ("azure", "Microsoft Azure"), ("microsoft", "Microsoft"), ("windows", "Microsoft"),
    ("netflix", "Netflix"), ("nflx", "Netflix"), ("tiktok", "TikTok"),
    ("bytedance", "TikTok / ByteDance"), ("spotify", "Spotify"), ("vivoglobal", "Vivo"),
]


# Known IP ranges for the big players — many (Meta, Microsoft) publish no PTR,
# so a CIDR check catches them when reverse-DNS can't. Checked first (instant).
_CIDR_ORGS_RAW = [
    ("157.240.0.0/16", "Meta / Instagram"), ("31.13.0.0/16", "Meta / Instagram"),
    ("57.144.0.0/14", "Meta / Instagram"), ("69.171.224.0/19", "Meta"),
    ("66.220.144.0/20", "Meta"), ("129.134.0.0/16", "Meta"), ("185.60.216.0/22", "Meta"),
    ("102.132.96.0/20", "Meta"), ("179.60.192.0/22", "Meta"), ("163.70.128.0/17", "Meta"),
    ("142.250.0.0/15", "Google"), ("142.251.0.0/16", "Google"), ("172.217.0.0/16", "Google"),
    ("216.58.192.0/19", "Google"), ("108.177.0.0/17", "Google"), ("74.125.0.0/16", "Google"),
    ("173.194.0.0/16", "Google"), ("64.233.160.0/19", "Google"), ("172.253.0.0/16", "Google"),
    ("104.16.0.0/13", "Cloudflare"), ("104.24.0.0/14", "Cloudflare"), ("172.64.0.0/13", "Cloudflare"),
    ("1.1.1.0/24", "Cloudflare"), ("13.32.0.0/15", "Amazon CloudFront"),
    ("23.192.0.0/11", "Akamai"), ("40.74.0.0/15", "Microsoft Azure"),
    ("20.0.0.0/8", "Microsoft Azure"), ("52.96.0.0/12", "Microsoft"),
]
_CIDR_ORGS = None


def _cidr_org(ip: str) -> str:
    global _CIDR_ORGS
    if _CIDR_ORGS is None:
        _CIDR_ORGS = [(ipaddress.ip_network(n), o) for n, o in _CIDR_ORGS_RAW]
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    for net, org in _CIDR_ORGS:
        if addr in net:
            return org
    return ""


def org_for_ip(ip: str, timeout: float = 1.2) -> str:
    """Best-effort destination owner. Known CIDR ranges first (instant, catches
    Meta/Google/etc. that publish no PTR), then reverse-DNS. '' if unknown."""
    cidr = _cidr_org(ip)
    if cidr:
        return cidr
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        host = socket.gethostbyaddr(ip)[0]
    except Exception:  # noqa: BLE001
        return ""
    finally:
        socket.setdefaulttimeout(old)
    low = host.lower()
    for kw, org in _ORG_HINTS:
        if kw in low:
            return org
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def resolve_name(ip: str, local_ip: str = "0.0.0.0") -> Optional[str]:
    """Try each resolver in order of how descriptive the name tends to be."""
    for resolver in (
        lambda: mdns_name(ip, local_ip),
        lambda: netbios_name(ip),
        lambda: reverse_dns(ip),
    ):
        try:
            name = resolver()
        except Exception:  # noqa: BLE001
            name = None
        if name:
            return name
    return None
