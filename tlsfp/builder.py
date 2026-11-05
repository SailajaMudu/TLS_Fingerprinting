"""Build raw TLS ClientHello / ServerHello records.

Used by the hand-crafted "custom TLS client", the fingerprint-spoofing demo
(replaying a JA3 or JA4_r string on the wire) and the unit tests.
"""
from __future__ import annotations

import os
import struct
from dataclasses import dataclass, field

DEFAULT_SIGALGS = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]


def u16(v: int) -> bytes:
    return struct.pack("!H", v)


def _vec(data: bytes, len_bytes: int) -> bytes:
    return len(data).to_bytes(len_bytes, "big") + data


@dataclass
class HelloSpec:
    version: int = 0x0303
    ciphers: list[int] = field(default_factory=list)
    extensions: list[int] = field(default_factory=list)       # wire order
    groups: list[int] = field(default_factory=list)
    point_formats: list[int] = field(default_factory=list)
    sigalgs: list[int] = field(default_factory=lambda: list(DEFAULT_SIGALGS))
    alpn: list[bytes] = field(default_factory=list)
    supported_versions: list[int] = field(default_factory=list)
    sni: str = ""


def _ext_body(ext: int, spec: HelloSpec) -> bytes:
    if ext == 0x0000:                                   # server_name
        name = spec.sni.encode("idna") if spec.sni else b""
        return _vec(b"\x00" + _vec(name, 2), 2)
    if ext == 0x000A:                                   # supported_groups
        return _vec(b"".join(u16(g) for g in spec.groups), 2)
    if ext == 0x000B:                                   # ec_point_formats
        return _vec(bytes(spec.point_formats), 1)
    if ext == 0x000D:                                   # signature_algorithms
        return _vec(b"".join(u16(s) for s in spec.sigalgs), 2)
    if ext == 0x0010:                                   # ALPN
        return _vec(b"".join(_vec(p, 1) for p in spec.alpn), 2)
    if ext == 0x002B:                                   # supported_versions
        versions = spec.supported_versions or [0x0304, 0x0303]
        return _vec(b"".join(u16(v) for v in versions), 1)
    if ext == 0x0005:                                   # status_request (OCSP)
        return b"\x01\x00\x00\x00\x00"
    if ext == 0x002D:                                   # psk_key_exchange_modes
        return b"\x01\x01"
    if ext == 0x001B:                                   # compress_certificate (brotli)
        return b"\x02\x00\x02"
    if ext == 0xFF01:                                   # renegotiation_info
        return b"\x00"
    if ext == 0x0033:                                   # key_share
        # Offer an X25519 share (random 32 bytes) when x25519 is a supported group.
        if 0x001D in spec.groups or not spec.groups:
            return _vec(u16(0x001D) + _vec(os.urandom(32), 2), 2)
        return _vec(b"", 2)
    if ext == 0x0015:                                   # padding
        return b"\x00" * 16
    if ext == 0x001C:                                   # record_size_limit
        return u16(0x4001)
    if ext == 0x0022:                                   # delegated_credentials
        return _vec(b"".join(u16(s) for s in spec.sigalgs[:4]), 2)
    # extended_master_secret (0x17), session_ticket (0x23), SCT (0x12),
    # encrypt_then_mac (0x16), post_handshake_auth (0x31) ... are valid empty.
    return b""


def build_client_hello(spec: HelloSpec) -> bytes:
    """Return a complete TLS record carrying a ClientHello built from `spec`."""
    exts = b"".join(u16(e) + _vec(_ext_body(e, spec), 2) for e in spec.extensions)
    body = (u16(spec.version) + os.urandom(32) + _vec(os.urandom(32), 1)
            + _vec(b"".join(u16(c) for c in spec.ciphers), 2)
            + _vec(b"\x00", 1)
            + (_vec(exts, 2) if spec.extensions else b""))
    handshake = b"\x01" + _vec(body, 3)
    return b"\x16\x03\x01" + _vec(handshake, 2)


def build_server_hello(version: int, cipher: int, extensions: list[tuple[int, bytes]]) -> bytes:
    exts = b"".join(u16(t) + _vec(d, 2) for t, d in extensions)
    body = (u16(version) + os.urandom(32) + _vec(b"", 1) + u16(cipher) + b"\x00"
            + (_vec(exts, 2) if extensions else b""))
    return b"\x16\x03\x03" + _vec(b"\x02" + _vec(body, 3), 2)


# ------------------------------------------------------------ spoofing helpers

def spec_from_ja3(ja3_full: str, sni: str = "") -> HelloSpec:
    """Turn a JA3 string 'ver,ciphers,exts,groups,pfs' back into a ClientHello spec."""
    parts = (ja3_full.split(",") + ["", "", "", "", ""])[:5]

    def ints(s: str) -> list[int]:
        return [int(x) for x in s.split("-") if x]

    spec = HelloSpec(version=int(parts[0]), ciphers=ints(parts[1]), extensions=ints(parts[2]),
                     groups=ints(parts[3]), point_formats=ints(parts[4]), sni=sni)
    spec.alpn = [b"h2", b"http/1.1"]
    # pre_shared_key (41) must carry a real ticket; drop it so the hello stays parseable
    spec.extensions = [e for e in spec.extensions if e != 41]
    return spec


_ALPN_GUESS = {"h2": b"h2", "h1": b"http/1.1", "h3": b"h3"}


def spec_from_ja4_r(ja4_r: str, sni: str = "") -> HelloSpec:
    """Turn a JA4_r string back into a ClientHello spec (order is the sorted one)."""
    a, ciphers, exts, *rest = ja4_r.split("_")
    sigalgs = rest[0] if rest else ""
    version = {"13": 0x0304, "12": 0x0303, "11": 0x0302, "10": 0x0301}.get(a[1:3], 0x0303)
    hexes = lambda s: [int(x, 16) for x in s.split(",") if x]   # noqa: E731
    ext_list = hexes(exts)
    if a[3] == "d":
        ext_list.insert(0, 0x0000)
    alpn_code = a[8:10]
    if alpn_code != "00":
        ext_list.append(0x0010)
    spec = HelloSpec(version=0x0303, ciphers=hexes(ciphers), extensions=ext_list,
                     groups=[0x001D, 0x0017, 0x0018], point_formats=[0],
                     sigalgs=hexes(sigalgs) or list(DEFAULT_SIGALGS),
                     alpn=[_ALPN_GUESS.get(alpn_code, b"http/1.1")], sni=sni)
    if version == 0x0304:
        spec.supported_versions = [0x0304, 0x0303]
    return spec
