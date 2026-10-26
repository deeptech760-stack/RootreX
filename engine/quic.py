"""quic.py — recover the SNI (server name) from QUIC Initial packets.

Modern mobile apps (Instagram/Reels, YouTube, etc.) talk HTTP/3 over QUIC on
UDP/443, so a TCP-only SNI sniffer sees nothing. QUIC Initial packets are
"encrypted", but with keys derived from a *public* salt + the connection ID
(RFC 9001 §5.2), so the ClientHello — and thus the SNI — is recoverable without
any secret. Standard technique (Wireshark does the same). It stays strictly
inside the TLS boundary: the destination *name* only, never payload content.

Large ClientHellos (Google/Meta) span several Initial packets, so `QuicSni`
reassembles CRYPTO fragments per flow until the SNI is readable. Only QUIC v1
(0x00000001) is handled.
"""
from __future__ import annotations

import hashlib
import hmac
import struct
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

QUIC_V1_SALT = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")


def _varint(data: bytes, off: int) -> tuple[int, int]:
    b0 = data[off]
    n = 1 << (b0 >> 6)
    val = b0 & 0x3F
    for i in range(1, n):
        val = (val << 8) | data[off + i]
    return val, off + n


def _expand_label(secret: bytes, label: bytes, length: int) -> bytes:
    full = b"tls13 " + label
    info = struct.pack("!H", length) + bytes([len(full)]) + full + b"\x00"
    return HKDFExpand(algorithm=hashes.SHA256(), length=length, info=info).derive(secret)


def _aes_ecb(key: bytes, data: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()  # noqa: S305 - RFC 9001 header protection
    return enc.update(data) + enc.finalize()


def _client_initial_secret(dcid: bytes) -> bytes:
    initial = hmac.new(QUIC_V1_SALT, dcid, hashlib.sha256).digest()  # HKDF-Extract
    return _expand_label(initial, b"client in", 32)


def decrypt_initial(payload: bytes) -> Optional[bytes]:
    """Decrypt a QUIC v1 Initial packet → its frame bytes, or None."""
    try:
        if len(payload) < 120 or (payload[0] & 0xC0) != 0xC0 or (payload[0] & 0x30) != 0x00:
            return None
        if int.from_bytes(payload[1:5], "big") != 1:
            return None
        off = 5
        dl = payload[off]; off += 1
        dcid = payload[off:off + dl]; off += dl
        sl = payload[off]; off += 1 + sl
        tl, off = _varint(payload, off); off += tl
        length, off = _varint(payload, off)
        pn_off = off

        secret = _client_initial_secret(dcid)
        key = _expand_label(secret, b"quic key", 16)
        iv = _expand_label(secret, b"quic iv", 12)
        hp = _expand_label(secret, b"quic hp", 16)

        mask = _aes_ecb(hp, payload[pn_off + 4:pn_off + 20])
        first = payload[0] ^ (mask[0] & 0x0F)
        pn_len = (first & 0x03) + 1
        pn_bytes = bytes(payload[pn_off + i] ^ mask[1 + i] for i in range(pn_len))
        pn = int.from_bytes(pn_bytes, "big")

        header = bytes([first]) + payload[1:pn_off] + pn_bytes
        ciphertext = payload[pn_off + pn_len:pn_off + length]
        nonce = bytes(a ^ b for a, b in zip(iv, pn.to_bytes(12, "big")))
        return AESGCM(key).decrypt(nonce, ciphertext, header)
    except Exception:  # noqa: BLE001
        return None


def crypto_chunks(plaintext: bytes) -> dict[int, bytes]:
    """Return {offset: data} for every CRYPTO frame in a decrypted payload."""
    chunks: dict[int, bytes] = {}
    i, n = 0, len(plaintext)
    try:
        while i < n:
            ftype, i = _varint(plaintext, i)
            if ftype in (0x00, 0x01):           # PADDING / PING
                continue
            if ftype == 0x06:                    # CRYPTO
                off, i = _varint(plaintext, i)
                ln, i = _varint(plaintext, i)
                chunks[off] = plaintext[i:i + ln]
                i += ln
            elif ftype in (0x02, 0x03):          # ACK (skip)
                _, i = _varint(plaintext, i)
                _, i = _varint(plaintext, i)
                rc, i = _varint(plaintext, i)
                _, i = _varint(plaintext, i)
                for _ in range(rc):
                    _, i = _varint(plaintext, i)
                    _, i = _varint(plaintext, i)
                if ftype == 0x03:
                    for _ in range(3):
                        _, i = _varint(plaintext, i)
            else:
                break
    except Exception:  # noqa: BLE001
        pass
    return chunks


def _reassemble(chunks: dict[int, bytes]) -> bytes:
    out, pos = bytearray(), 0
    for off in sorted(chunks):
        if off <= pos < off + len(chunks[off]):
            out += chunks[off][pos - off:]
            pos = len(out)
        elif off > pos:
            break
    return bytes(out)


def sni_from_handshake(hs: bytes) -> Optional[str]:
    """SNI from a (possibly partial) TLS ClientHello handshake message."""
    try:
        if len(hs) < 44 or hs[0] != 0x01:        # ClientHello
            return None
        pos = 4 + 2 + 32                          # hs header + version + random
        pos += 1 + hs[pos]                        # session id
        cs_len = int.from_bytes(hs[pos:pos + 2], "big"); pos += 2 + cs_len
        pos += 1 + hs[pos]                        # compression methods
        ext_total = int.from_bytes(hs[pos:pos + 2], "big"); pos += 2
        end = min(pos + ext_total, len(hs))
        while pos + 4 <= end:
            etype = int.from_bytes(hs[pos:pos + 2], "big")
            elen = int.from_bytes(hs[pos + 2:pos + 4], "big")
            pos += 4
            if etype == 0x0000:                   # server_name
                name_len = int.from_bytes(hs[pos + 3:pos + 5], "big")
                name = hs[pos + 5:pos + 5 + name_len]
                if len(name) < name_len:
                    return None                   # not fully reassembled yet
                try:
                    return name.decode("idna") or None
                except Exception:  # noqa: BLE001
                    return name.decode("utf-8", "ignore") or None
            pos += elen
    except Exception:  # noqa: BLE001
        return None
    return None


def extract_sni(payload: bytes) -> Optional[str]:
    """Single-packet convenience (small ClientHellos only)."""
    pt = decrypt_initial(payload)
    if pt is None:
        return None
    return sni_from_handshake(_reassemble(crypto_chunks(pt)))


class QuicSni:
    """Reassembles CRYPTO fragments across a flow's Initial packets to recover SNI."""

    def __init__(self, max_flows: int = 512) -> None:
        self._buf: dict = {}       # flow -> {offset: data}
        self._done: set = set()    # flows already resolved
        self._max = max_flows

    def feed(self, flow, payload: bytes) -> Optional[str]:
        if flow in self._done:
            return None
        pt = decrypt_initial(payload)
        if pt is None:
            return None
        buf = self._buf.setdefault(flow, {})
        for off, data in crypto_chunks(pt).items():
            if off not in buf or len(data) > len(buf[off]):
                buf[off] = data
        sni = sni_from_handshake(_reassemble(buf))
        if sni:
            self._done.add(flow)
            self._buf.pop(flow, None)
            if len(self._done) > self._max * 2:
                self._done.clear()
            return sni
        if len(self._buf) > self._max:
            self._buf.pop(next(iter(self._buf)), None)
        return None
