"""JA3 / JA3S (Salesforce) and JA4 / JA4S (FoxIO) fingerprint computation.

JA3  : https://github.com/salesforce/ja3
JA4+ : https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .tls_parser import (EXT_ALPN, EXT_SERVER_NAME, ClientHello, ServerHello,
                         is_grease)

_EMPTY_HASH = "000000000000"

_TLS_VERSIONS = {
    0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10",
    0x0300: "s3", 0x0002: "s2",
    0xFEFF: "d1", 0xFEFD: "d2", 0xFEFC: "d3",
}


@dataclass
class ClientFingerprint:
    ja3: str
    ja3_full: str
    ja4: str
    ja4_r: str


@dataclass
class ServerFingerprint:
    ja3s: str
    ja3s_full: str
    ja4s: str
    ja4s_r: str


def _md5(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()


def _sha12(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:12]


def _no_grease(values) -> list[int]:
    return [v for v in values if not is_grease(v)]


def _dash(values) -> str:
    return "-".join(str(v) for v in values)


# ---------------------------------------------------------------- JA3 / JA3S

def ja3_string(ch: ClientHello) -> str:
    """SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats"""
    return ",".join([
        str(ch.legacy_version),
        _dash(_no_grease(ch.ciphers)),
        _dash(_no_grease(ch.extensions)),
        _dash(_no_grease(ch.supported_groups)),
        _dash(ch.ec_point_formats),
    ])


def ja3s_string(sh: ServerHello) -> str:
    """SSLVersion,Cipher,Extensions"""
    return ",".join([str(sh.legacy_version), str(sh.cipher), _dash(_no_grease(sh.extensions))])


# ---------------------------------------------------------------- JA4 / JA4S

def _version_code(version: int) -> str:
    return _TLS_VERSIONS.get(version, "00")


def _is_alnum(b: int) -> bool:
    return 0x30 <= b <= 0x39 or 0x41 <= b <= 0x5A or 0x61 <= b <= 0x7A


def _alpn_code(alpn: bytes | None) -> str:
    if not alpn:
        return "00"
    if _is_alnum(alpn[0]) and _is_alnum(alpn[-1]):
        return chr(alpn[0]) + chr(alpn[-1])
    h = alpn.hex()
    return h[0] + h[-1]


def _hex4(values) -> list[str]:
    return [f"{v:04x}" for v in values]


def ja4_parts(ch: ClientHello, transport: str = "t") -> tuple[str, str, str]:
    """Return (ja4_a, cipher_string, extension_string) - the pre-hash JA4 parts."""
    versions = _no_grease(ch.supported_versions)
    version = max(versions) if versions else ch.legacy_version
    ciphers = _no_grease(ch.ciphers)
    exts = _no_grease(ch.extensions)
    sni_flag = "d" if EXT_SERVER_NAME in exts else "i"
    alpn = _alpn_code(ch.alpn[0] if ch.alpn else None)
    ja4_a = (f"{transport}{_version_code(version)}{sni_flag}"
             f"{min(len(ciphers), 99):02d}{min(len(exts), 99):02d}{alpn}")

    cipher_str = ",".join(sorted(_hex4(ciphers)))
    ext_str = ",".join(sorted(_hex4(e for e in exts if e not in (EXT_SERVER_NAME, EXT_ALPN))))
    sigalgs = ",".join(_hex4(_no_grease(ch.signature_algorithms)))
    if sigalgs:
        ext_str = f"{ext_str}_{sigalgs}"
    return ja4_a, cipher_str, ext_str


def ja4(ch: ClientHello, transport: str = "t") -> tuple[str, str]:
    """Return (ja4, ja4_r)."""
    a, c_str, e_str = ja4_parts(ch, transport)
    b = _sha12(c_str) if c_str else _EMPTY_HASH
    c = _sha12(e_str) if e_str else _EMPTY_HASH
    return f"{a}_{b}_{c}", f"{a}_{c_str}_{e_str}"


def ja4s(sh: ServerHello, transport: str = "t") -> tuple[str, str]:
    """Return (ja4s, ja4s_r)."""
    exts = _no_grease(sh.extensions)
    version = sh.selected_version or sh.legacy_version
    a = (f"{transport}{_version_code(version)}{min(len(exts), 99):02d}"
         f"{_alpn_code(sh.alpn)}")
    b = f"{sh.cipher:04x}"
    ext_str = ",".join(_hex4(exts))          # original order, not sorted
    c = _sha12(ext_str) if ext_str else _EMPTY_HASH
    return f"{a}_{b}_{c}", f"{a}_{b}_{ext_str}"


# ---------------------------------------------------------------- public API

def client_fingerprint(ch: ClientHello) -> ClientFingerprint:
    full = ja3_string(ch)
    j4, j4r = ja4(ch)
    return ClientFingerprint(ja3=_md5(full), ja3_full=full, ja4=j4, ja4_r=j4r)


def server_fingerprint(sh: ServerHello) -> ServerFingerprint:
    full = ja3s_string(sh)
    j4s, j4sr = ja4s(sh)
    return ServerFingerprint(ja3s=_md5(full), ja3s_full=full, ja4s=j4s, ja4s_r=j4sr)
