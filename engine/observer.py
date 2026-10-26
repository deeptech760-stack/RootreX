"""observer.py — destination visibility + on-path forwarding.

Once a device is routed through us (jammer.route), the observer does two jobs
on the same packet stream:

  1. **Forward** redirected IP packets to their real next hop, so the target
     stays online while we watch (userspace forwarding — no registry/reboot).
  2. **Read destinations only**: the domain a device is reaching, via plaintext
     DNS queries and the TLS SNI in the ClientHello. It records destination IPs,
     ports, connection counts, byte totals and timing — never payload content.

The TLS boundary is the whole point: we can see *that* a device contacted
``instagram.com`` and how much data moved, but the encrypted bytes inside the
tunnel are unreadable, and RootreX never attempts to read them.
"""
from __future__ import annotations

import hashlib
import ipaddress
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, asdict
from typing import Optional

from scapy.all import ARP, DNS, DNSQR, IP, TCP, UDP, Ether, AsyncSniffer, sendp

from . import identify, net, quic

log = logging.getLogger("rootrex.observer")

MAX_CONNS_PER_DEVICE = 40   # keep only the latest N destinations per device; evict oldest


# --------------------------------------------------------------- SNI parsing
def parse_tls_sni(payload: bytes) -> Optional[str]:
    """Extract the SNI host from a TLS ClientHello. Reads only the cleartext
    handshake header — never application data. Returns None if not a ClientHello
    or no SNI present."""
    try:
        if len(payload) < 43 or payload[0] != 0x16:  # 0x16 = handshake
            return None
        # TLS record header = 5 bytes; handshake type at offset 5 must be 0x01.
        if payload[5] != 0x01:  # ClientHello
            return None
        pos = 5 + 4 + 2 + 32  # record(5) + hs header(4) + version(2) + random(32)
        session_id_len = payload[pos]; pos += 1 + session_id_len
        cipher_len = int.from_bytes(payload[pos:pos + 2], "big"); pos += 2 + cipher_len
        comp_len = payload[pos]; pos += 1 + comp_len
        ext_total = int.from_bytes(payload[pos:pos + 2], "big"); pos += 2
        end = pos + ext_total
        while pos + 4 <= end:
            etype = int.from_bytes(payload[pos:pos + 2], "big")
            elen = int.from_bytes(payload[pos + 2:pos + 4], "big")
            pos += 4
            if etype == 0x0000:  # server_name
                # server_name_list(2) + name_type(1) + name_len(2) + name
                name_len = int.from_bytes(payload[pos + 3:pos + 5], "big")
                name = payload[pos + 5:pos + 5 + name_len]
                # Python's idna codec rejects non-strict error handlers, so try it
                # plainly and fall back to utf-8 (punycode A-labels survive either way).
                try:
                    return name.decode("idna") or None
                except Exception:  # noqa: BLE001
                    return name.decode("utf-8", "ignore") or None
            pos += elen
    except Exception:  # noqa: BLE001 - never let a malformed packet crash capture
        return None
    return None


def parse_tls_alpn(payload: bytes) -> str:
    """Extract the ALPN list from a TLS ClientHello (h2 / http/1.1 / etc.)."""
    try:
        if len(payload) < 44 or payload[0] != 0x16 or payload[5] != 0x01:
            return ""
        pos = 5 + 4 + 2 + 32
        pos += 1 + payload[pos]
        cl = int.from_bytes(payload[pos:pos + 2], "big"); pos += 2 + cl
        pos += 1 + payload[pos]
        ext_total = int.from_bytes(payload[pos:pos + 2], "big"); pos += 2
        end = min(pos + ext_total, len(payload))
        while pos + 4 <= end:
            etype = int.from_bytes(payload[pos:pos + 2], "big")
            elen = int.from_bytes(payload[pos + 2:pos + 4], "big")
            pos += 4
            if etype == 0x0010:  # application_layer_protocol_negotiation
                lpos, estop, protos = pos + 2, pos + elen, []
                while lpos < estop and lpos < len(payload):
                    plen = payload[lpos]; lpos += 1
                    protos.append(payload[lpos:lpos + plen].decode(errors="ignore"))
                    lpos += plen
                return ",".join(p for p in protos if p)
            pos += elen
    except Exception:  # noqa: BLE001
        return ""
    return ""


_GREASE = {0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
           0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa}


def parse_ja3(payload: bytes) -> str:
    """JA3 fingerprint of a TLS ClientHello — identifies the *client app/library*
    (the same hash across connections = the same app). Returns the md5 hex."""
    try:
        if len(payload) < 44 or payload[0] != 0x16 or payload[5] != 0x01:
            return ""
        ver = int.from_bytes(payload[9:11], "big")
        pos = 5 + 4 + 2 + 32
        pos += 1 + payload[pos]                      # session id
        cs_len = int.from_bytes(payload[pos:pos + 2], "big"); pos += 2
        ciphers = [c for i in range(0, cs_len, 2)
                   if (c := int.from_bytes(payload[pos + i:pos + i + 2], "big")) not in _GREASE]
        pos += cs_len
        pos += 1 + payload[pos]                      # compression methods
        ext_total = int.from_bytes(payload[pos:pos + 2], "big"); pos += 2
        end = min(pos + ext_total, len(payload))
        exts, groups, formats = [], [], []
        while pos + 4 <= end:
            et = int.from_bytes(payload[pos:pos + 2], "big")
            el = int.from_bytes(payload[pos + 2:pos + 4], "big")
            pos += 4
            if et not in _GREASE:
                exts.append(et)
            if et == 0x000A:                         # supported_groups
                glen = int.from_bytes(payload[pos:pos + 2], "big")
                groups = [g for i in range(2, 2 + glen, 2)
                          if (g := int.from_bytes(payload[pos + i:pos + i + 2], "big")) not in _GREASE]
            elif et == 0x000B:                       # ec_point_formats
                flen = payload[pos]
                formats = list(payload[pos + 1:pos + 1 + flen])
            pos += el
        s = ",".join([str(ver), "-".join(map(str, ciphers)), "-".join(map(str, exts)),
                      "-".join(map(str, groups)), "-".join(map(str, formats))])
        return hashlib.md5(s.encode()).hexdigest()
    except Exception:  # noqa: BLE001
        return ""


def _proto_name(c) -> str:
    if c.protocol == "QUIC":
        return "HTTP/3"
    if c.protocol == "TLS":
        if "h2" in c.alpn:
            return "HTTP/2"
        if "http/1.1" in c.alpn:
            return "HTTP/1.1"
        return "TLS"
    if c.protocol == "HTTP":
        return "HTTP (plain)"
    if c.protocol == "DNS":
        return "DNS"
    return c.protocol or "TCP"


def _classify(up: int, down: int, dur: float, nconns: int) -> str:
    if down / max(dur, 1) > 150_000:
        return "streaming"
    if up > down and up > 300_000:
        return "uploading"
    if down > 80_000 or nconns > 6:
        return "browsing"
    return "idle"


# ------------------------------------------------------------- metadata model
@dataclass
class Conn:
    dst_ip: str
    port: int
    domain: str = ""          # resolved via DNS/SNI when known
    org: str = ""             # destination owner from reverse-DNS (when no SNI)
    protocol: str = ""        # "TLS" | "DNS" | "QUIC" | "HTTP" | "TCP" | "UDP"
    packets: int = 0
    bytes: int = 0
    bytes_up: int = 0         # device -> internet
    bytes_down: int = 0       # internet -> device
    alpn: str = ""            # app protocol from the handshake (h2 / h3 / http/1.1)
    ja3: str = ""             # TLS ClientHello fingerprint (identifies the client app)
    info: str = ""            # extra detail (e.g. a plaintext HTTP request line)
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    encrypted_payload: bool = False  # True for TLS: destination visible, content not

    def as_dict(self) -> dict:
        d = asdict(self)
        d["first_seen"] = round(self.first_seen, 3)
        d["last_seen"] = round(self.last_seen, 3)
        dur = max(self.last_seen - self.first_seen, 0.001)
        d["duration"] = round(self.last_seen - self.first_seen, 1)
        d["rate"] = round(self.bytes / dur)   # bytes/sec
        return d


@dataclass
class DeviceMeta:
    ip: str
    mac: str
    conns: dict[tuple, Conn] = field(default_factory=dict)  # (dst_ip, port) -> Conn
    dns_names: dict[str, str] = field(default_factory=dict)  # ip -> last domain
    user_agent: str = ""      # from any plaintext HTTP the device sends

    def summary(self) -> dict:
        conns = sorted(self.conns.values(), key=lambda c: c.last_seen, reverse=True)
        first = min((c.first_seen for c in conns), default=0.0)
        last = max((c.last_seen for c in conns), default=0.0)
        total_up = sum(c.bytes_up for c in conns)
        total_down = sum(c.bytes_down for c in conns)
        dur = max(last - first, 0.001)
        protocols: dict[str, int] = {}
        for c in conns:
            name = _proto_name(c)
            protocols[name] = protocols.get(name, 0) + c.bytes
        return {
            "ip": self.ip,
            "mac": self.mac,
            "domains": sorted({c.domain for c in conns if c.domain}),
            "connections": [c.as_dict() for c in conns],
            "total_bytes": sum(c.bytes for c in conns),
            "total_up": total_up,
            "total_down": total_down,
            "total_conns": len(conns),
            "duration": round(last - first, 1),
            "rate_down": round(total_down / dur),
            "rate_up": round(total_up / dur),
            "protocols": protocols,
            "activity": _classify(total_up, total_down, dur, len(conns)),
            "ja3": next((c.ja3 for c in conns if c.ja3), ""),
            "user_agent": self.user_agent,
        }


class Observer:
    def __init__(self, ctx: net.NetContext) -> None:
        self.ctx = ctx
        self._lock = threading.RLock()
        self._meta: dict[str, DeviceMeta] = {}       # target_ip -> DeviceMeta
        self._targets: dict[str, str] = {}           # target_ip -> target_mac
        self._sniffer: Optional[AsyncSniffer] = None
        self._forwarding = True
        self._capture_iface: Optional[str] = None  # override iface (AP mode)
        self._quic = quic.QuicSni()   # reassembles QUIC Initials -> SNI
        self._org_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="rx-org")
        self._org: dict[str, str] = {}       # dst_ip -> owner
        self._org_tried: set[str] = set()
        # Mode 1 (route-through): record only allowlisted targets.
        # Mode 2 (Test-AP): we ARE the gateway, so record every private client.
        self._observe_all = False

    # ------------------------------------------------------------- targets
    def add_target(self, ip: str, mac: str) -> None:
        with self._lock:
            self._targets[ip] = mac.lower()
            self._meta.setdefault(ip, DeviceMeta(ip=ip, mac=mac.lower()))

    def remove_target(self, ip: str) -> None:
        with self._lock:
            self._targets.pop(ip, None)

    def set_observe_all(self, value: bool) -> None:
        with self._lock:
            self._observe_all = value

    def set_iface(self, iface: Optional[str]) -> None:
        """Capture on a specific interface (e.g. the hotspot adapter in AP mode).
        None = back to the main interface."""
        self._capture_iface = iface

    # ------------------------------------------------------------- capture
    def start(self) -> None:
        if self._sniffer is not None:
            return
        iface = self._capture_iface or self.ctx.iface
        # Capture IP + ARP at L2; we filter in the callback so we can both
        # forward and inspect. prn runs in the sniffer thread.
        self._sniffer = AsyncSniffer(
            iface=iface, store=False, prn=self._on_packet,
            filter="ip or arp",
        )
        self._sniffer.start()
        log.info("observer capture started on %s", iface)

    def stop(self) -> None:
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:  # noqa: BLE001
                pass
            self._sniffer = None
            log.info("observer capture stopped")

    # ------------------------------------------------------------- forwarding
    def _forward(self, pkt) -> None:
        """Relay a redirected IP packet to its real next hop (keeps target online)."""
        if not self._forwarding or Ether not in pkt or IP not in pkt:
            return
        eth = pkt[Ether]
        if (eth.dst or "").lower() != self.ctx.local_mac:  # only packets steered to us
            return
        ip = pkt[IP]
        with self._lock:
            targets = dict(self._targets)
        # Target -> outside world: send on to the real gateway.
        if ip.src in targets:
            next_hop = self.ctx.gateway_mac
        # Outside world -> target: send on to the target.
        elif ip.dst in targets:
            next_hop = targets[ip.dst]
        else:
            return
        if not next_hop:
            return
        fwd = pkt.copy()
        fwd[Ether].src = self.ctx.local_mac
        fwd[Ether].dst = next_hop
        try:
            sendp(fwd, iface=self.ctx.iface, verbose=0)
        except Exception:  # noqa: BLE001
            pass

    # ------------------------------------------------------------- inspection
    def _on_packet(self, pkt) -> None:
        try:
            if ARP in pkt:
                return  # jammer owns ARP; nothing to read here
            if IP not in pkt:
                return
            self._forward(pkt)
            self._inspect(pkt)
        except Exception:  # noqa: BLE001 - capture must never die on one packet
            log.debug("packet handling error", exc_info=True)

    def _device_for(self, pkt, ip):
        """Return (dev_ip, dev_mac, direction) for the device this packet concerns,
        or None to ignore it. In observe-all (AP) mode the device is the private
        hotspot-side endpoint; otherwise it must be an explicit route target."""
        with self._lock:
            targets = dict(self._targets)
            observe_all = self._observe_all
        eth = pkt[Ether] if Ether in pkt else None
        if observe_all:
            try:
                src_priv = ip.src != self.ctx.local_ip and ipaddress.ip_address(ip.src).is_private
                dst_priv = ip.dst != self.ctx.local_ip and ipaddress.ip_address(ip.dst).is_private
            except ValueError:
                return None
            if src_priv:
                return ip.src, (eth.src.lower() if eth and eth.src else ""), "out"
            if dst_priv:
                return ip.dst, (eth.dst.lower() if eth and eth.dst else ""), "in"
            return None
        if ip.src in targets:
            return ip.src, targets[ip.src], "out"
        if ip.dst in targets:
            return ip.dst, targets[ip.dst], "in"
        return None

    def _cap(self, meta: "DeviceMeta") -> None:
        """Keep only the latest MAX_CONNS_PER_DEVICE destinations, dropping the
        oldest by last-seen — bounds memory and keeps the UI snappy."""
        extra = len(meta.conns) - MAX_CONNS_PER_DEVICE
        if extra <= 0:
            return
        for key in sorted(meta.conns, key=lambda k: meta.conns[k].last_seen)[:extra]:
            meta.conns.pop(key, None)

    def _inspect(self, pkt) -> None:
        ip = pkt[IP]
        dev = self._device_for(pkt, ip)
        if dev is None:
            return
        dev_ip, dev_mac, direction = dev

        with self._lock:
            meta = self._meta.setdefault(dev_ip, DeviceMeta(ip=dev_ip, mac=dev_mac))

            # DNS: learn ip -> domain mappings and record the lookup itself.
            if UDP in pkt and (pkt[UDP].dport == 53 or pkt[UDP].sport == 53) and DNS in pkt:
                self._read_dns(meta, pkt)
                self._cap(meta)
                return

            # QUIC / HTTP-3 over UDP/443 — record it and recover the SNI (name only).
            if UDP in pkt and (pkt[UDP].dport == 443 or pkt[UDP].sport == 443):
                udp = pkt[UDP]
                remote_ip = ip.dst if direction == "out" else ip.src
                key = (remote_ip, 443, "quic")
                conn = meta.conns.get(key)
                if conn is None:
                    conn = Conn(dst_ip=remote_ip, port=443, protocol="QUIC",
                                domain=meta.dns_names.get(remote_ip, ""),
                                encrypted_payload=True)
                    meta.conns[key] = conn
                plen = len(bytes(pkt))
                conn.packets += 1
                conn.bytes += plen
                if direction == "out":
                    conn.bytes_up += plen
                else:
                    conn.bytes_down += plen
                conn.last_seen = time.time()
                conn.alpn = conn.alpn or "h3"   # QUIC is HTTP/3
                if direction == "out":
                    try:
                        sni = self._quic.feed(
                            (ip.src, udp.sport, ip.dst, udp.dport), bytes(udp.payload))
                    except Exception:  # noqa: BLE001
                        sni = None
                    if sni:
                        conn.domain = sni
                        meta.dns_names[remote_ip] = sni
                self._tag_org(conn, remote_ip)
                self._cap(meta)
                return

            if TCP in pkt:
                tcp = pkt[TCP]
                remote_ip = ip.dst if direction == "out" else ip.src
                remote_port = tcp.dport if direction == "out" else tcp.sport
                key = (remote_ip, int(remote_port))
                conn = meta.conns.get(key)
                if conn is None:
                    conn = Conn(dst_ip=remote_ip, port=int(remote_port),
                                protocol="TCP",
                                domain=meta.dns_names.get(remote_ip, ""))
                    meta.conns[key] = conn
                plen = len(bytes(pkt))
                conn.packets += 1
                conn.bytes += plen
                if direction == "out":
                    conn.bytes_up += plen
                else:
                    conn.bytes_down += plen
                conn.last_seen = time.time()

                payload = bytes(tcp.payload) if direction == "out" else b""
                # TLS ClientHello on egress -> SNI + ALPN (destination, not content).
                if direction == "out" and remote_port == 443 and payload:
                    sni = parse_tls_sni(payload)
                    if sni:
                        conn.domain = sni
                        conn.protocol = "TLS"
                        conn.encrypted_payload = True
                        meta.dns_names[remote_ip] = sni
                    alpn = parse_tls_alpn(payload)
                    if alpn:
                        conn.alpn = alpn
                    if not conn.ja3:
                        ja3 = parse_ja3(payload)
                        if ja3:
                            conn.ja3 = ja3
                # Plaintext HTTP -> the real URL + User-Agent (the device names itself).
                elif direction == "out" and remote_port == 80 and payload[:5] in (
                        b"GET /", b"POST ", b"HEAD ", b"PUT /", b"OPTIO", b"PATCH", b"DELET"):
                    self._parse_http(conn, meta, payload)
                self._tag_org(conn, remote_ip)
                self._cap(meta)

    def _parse_http(self, conn: "Conn", meta: "DeviceMeta", payload: bytes) -> None:
        try:
            head = payload.split(b"\r\n\r\n", 1)[0].split(b"\r\n")
            parts = head[0].decode(errors="ignore").split(" ")
            method, path = (parts + ["", ""])[:2]
            host = ua = ""
            for line in head[1:]:
                low = line.lower()
                if low.startswith(b"host:"):
                    host = line[5:].strip().decode(errors="ignore")
                elif low.startswith(b"user-agent:"):
                    ua = line[11:].strip().decode(errors="ignore")
            conn.protocol = "HTTP"
            if host:
                conn.domain = host
            conn.info = (method + " " + path)[:90]
            if ua and not meta.user_agent:
                meta.user_agent = ua[:140]
        except Exception:  # noqa: BLE001
            pass

    def _tag_org(self, conn: "Conn", remote_ip: str) -> None:
        """Attach the destination owner (reverse-DNS) when we have no SNI/domain."""
        if conn.domain:
            return
        org = self._org.get(remote_ip)
        if org:
            conn.org = org
        elif remote_ip not in self._org_tried:
            self._org_tried.add(remote_ip)
            self._org_pool.submit(self._resolve_org, remote_ip)

    def _resolve_org(self, ip: str) -> None:
        try:
            org = identify.org_for_ip(ip)
        except Exception:  # noqa: BLE001
            org = ""
        if not org:
            return
        with self._lock:
            self._org[ip] = org
            for meta in self._meta.values():
                for c in meta.conns.values():
                    if c.dst_ip == ip and not c.domain and not c.org:
                        c.org = org

    def _read_dns(self, meta: DeviceMeta, pkt) -> None:
        dns = pkt[DNS]
        # Query name (what the device is looking up).
        if dns.qr == 0 and dns.qd is not None:
            try:
                qname = dns.qd.qname.decode(errors="ignore").rstrip(".")
            except Exception:  # noqa: BLE001
                qname = ""
            if qname:
                key = (pkt[IP].dst, 53)
                conn = meta.conns.get(key) or Conn(dst_ip=pkt[IP].dst, port=53,
                                                   protocol="DNS")
                conn.domain = qname
                conn.protocol = "DNS"
                conn.packets += 1
                conn.bytes += len(bytes(pkt))
                conn.last_seen = time.time()
                meta.conns[key] = conn
        # Answers: map resolved IPs back to the name for later TCP conns.
        if dns.qr == 1 and dns.an is not None:
            try:
                name = dns.qd.qname.decode(errors="ignore").rstrip(".")
            except Exception:  # noqa: BLE001
                name = ""
            for i in range(dns.ancount or 0):
                try:
                    rr = dns.an[i]
                    if getattr(rr, "type", None) == 1:  # A record
                        meta.dns_names[rr.rdata] = name
                except Exception:  # noqa: BLE001
                    break

    # ------------------------------------------------------------- snapshot
    def snapshot(self) -> list[dict]:
        with self._lock:
            return [m.summary() for m in self._meta.values()]

    def clear(self) -> None:
        with self._lock:
            self._meta.clear()
