"""Unit tests for the observer — SNI/DNS parsing, per-device metadata, the TLS
boundary, observe-all grouping, and on-path forwarding."""
from __future__ import annotations

from scapy.all import DNS, DNSQR, DNSRR, IP, TCP, UDP, Ether, Raw

from engine.observer import Observer, parse_tls_sni


def build_client_hello(host: bytes = b"example.com") -> bytes:
    """A minimal, valid TLS ClientHello carrying an SNI for `host`."""
    sni = b"\x00" + len(host).to_bytes(2, "big") + host
    sni_list = len(sni).to_bytes(2, "big") + sni
    ext = b"\x00\x00" + len(sni_list).to_bytes(2, "big") + sni_list
    exts = len(ext).to_bytes(2, "big") + ext
    body = (b"\x03\x03" + b"\x00" * 32 + b"\x00"
            + b"\x00\x02\x13\x01" + b"\x01\x00" + exts)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs


def test_parse_tls_sni_extracts_host():
    assert parse_tls_sni(build_client_hello(b"example.com")) == "example.com"


def test_parse_tls_sni_rejects_non_clienthello():
    assert parse_tls_sni(b"\x17\x03\x03\x00\x03abc") is None   # application data, not handshake
    assert parse_tls_sni(b"") is None


def test_observer_records_dns_query(ctx):
    o = Observer(ctx)
    o.add_target("192.168.1.50", "dd:dd:dd:dd:dd:dd")
    pkt = (Ether() / IP(src="192.168.1.50", dst="192.168.1.1")
           / UDP(sport=5000, dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com")))
    o._on_packet(pkt)
    snap = o.snapshot()
    domains = [c["domain"] for d in snap for c in d["connections"]]
    assert any("example.com" in d for d in domains)


def test_observer_tls_shows_destination_not_content(ctx):
    o = Observer(ctx)
    o.add_target("192.168.1.50", "dd:dd:dd:dd:dd:dd")
    pkt = (Ether() / IP(src="192.168.1.50", dst="93.184.216.34")
           / TCP(sport=4001, dport=443) / Raw(load=build_client_hello(b"example.com")))
    o._on_packet(pkt)
    conns = o.snapshot()[0]["connections"]
    tls = [c for c in conns if c["protocol"] == "TLS"]
    assert tls, "a 443 ClientHello should be recorded as TLS"
    assert tls[0]["domain"] == "example.com"
    assert tls[0]["encrypted_payload"] is True   # the honesty flag: we see where, not what


def test_observe_all_groups_by_private_client(ctx):
    o = Observer(ctx)
    o.set_observe_all(True)                       # AP mode: we are the gateway
    pkt = (Ether() / IP(src="192.168.137.5", dst="1.1.1.1")
           / TCP(sport=5000, dport=443) / Raw(load=build_client_hello(b"cloudflare.com")))
    o._on_packet(pkt)
    snap = o.snapshot()
    assert snap and snap[0]["ip"] == "192.168.137.5"


def test_observe_all_ignores_our_own_traffic(ctx):
    o = Observer(ctx)
    o.set_observe_all(True)
    # purely external<->external or involving only our own IP should not be grouped
    pkt = Ether() / IP(src="8.8.8.8", dst="1.1.1.1") / TCP(dport=443)
    o._on_packet(pkt)
    assert o.snapshot() == []


def test_forward_rewrites_to_real_gateway(ctx, monkeypatch):
    o = Observer(ctx)
    o.add_target("192.168.1.50", "dd:dd:dd:dd:dd:dd")
    sent = []
    monkeypatch.setattr("engine.observer.sendp", lambda p, **k: sent.append(p))
    # a target packet steered to us (Ether.dst = our mac) heading out
    pkt = (Ether(src="dd:dd:dd:dd:dd:dd", dst=ctx.local_mac)
           / IP(src="192.168.1.50", dst="8.8.8.8") / TCP())
    o._forward(pkt)
    assert sent, "a redirected target packet must be forwarded"
    assert sent[0][Ether].dst == ctx.gateway_mac


def test_forward_ignores_packets_not_for_us(ctx, monkeypatch):
    o = Observer(ctx)
    o.add_target("192.168.1.50", "dd:dd:dd:dd:dd:dd")
    sent = []
    monkeypatch.setattr("engine.observer.sendp", lambda p, **k: sent.append(p))
    pkt = (Ether(src="dd:dd:dd:dd:dd:dd", dst="ee:ee:ee:ee:ee:ee")
           / IP(src="192.168.1.50", dst="8.8.8.8") / TCP())
    o._forward(pkt)
    assert sent == []
