"""Dependency-free parser for TLS ClientHello / ServerHello handshake messages.

Only the fields needed for JA3/JA3S/JA4/JA4S are decoded. The parser works on a
reassembled TCP byte stream (see flows.py), so a ClientHello that spans several
TCP segments or several TLS records (common with post-quantum key shares) is
handled correctly.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

RECORD_HANDSHAKE = 0x16
HS_CLIENT_HELLO = 1
HS_SERVER_HELLO = 2

EXT_SERVER_NAME = 0x0000
EXT_SUPPORTED_GROUPS = 0x000A
EXT_EC_POINT_FORMATS = 0x000B
EXT_SIGNATURE_ALGORITHMS = 0x000D
EXT_ALPN = 0x0010
EXT_SUPPORTED_VERSIONS = 0x002B

MAX_RECORD_LEN = 2**14 + 2048
MAX_HANDSHAKE_LEN = 2**17

# ServerHello.random value that marks a TLS 1.3 HelloRetryRequest (RFC 8446 4.1.3)
HRR_RANDOM = bytes.fromhex(
    "CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C"
)


def is_grease(value: int) -> bool:
    """RFC 8701 GREASE values: 0x0a0a, 0x1a1a, ... 0xfafa."""
    return (value & 0x0F0F) == 0x0A0A and (value >> 8) == (value & 0xFF)


class TLSParseError(ValueError):
    """Raised when bytes are definitely not a well-formed TLS hello."""


class _Reader:
    __slots__ = ("data", "pos")

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise TLSParseError("truncated field")
        chunk = self.data[self.pos:self.pos + n]
        self.pos += n
        return chunk

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return struct.unpack("!H", self.take(2))[0]

    def u24(self) -> int:
        return int.from_bytes(self.take(3), "big")

    def vec(self, len_bytes: int) -> bytes:
        n = {1: self.u8, 2: self.u16, 3: self.u24}[len_bytes]()
        return self.take(n)

    def remaining(self) -> int:
        return len(self.data) - self.pos


def _u16_list(data: bytes) -> list[int]:
    if len(data) % 2:
        raise TLSParseError("odd-length u16 list")
    return [v for (v,) in struct.iter_unpack("!H", data)]


@dataclass
class ClientHello:
    legacy_version: int
    ciphers: list[int]
    extensions: list[int]                      # wire order, GREASE included
    ext_data: dict[int, bytes] = field(default_factory=dict, repr=False)
    sni: str | None = None
    supported_groups: list[int] = field(default_factory=list)
    ec_point_formats: list[int] = field(default_factory=list)
    signature_algorithms: list[int] = field(default_factory=list)
    alpn: list[bytes] = field(default_factory=list)
    supported_versions: list[int] = field(default_factory=list)


@dataclass
class ServerHello:
    legacy_version: int
    cipher: int
    extensions: list[int]
    ext_data: dict[int, bytes] = field(default_factory=dict, repr=False)
    selected_version: int | None = None
    alpn: bytes | None = None
    is_hello_retry: bool = False


def _parse_extensions(r: _Reader) -> tuple[list[int], dict[int, bytes]]:
    order: list[int] = []
    data: dict[int, bytes] = {}
    if r.remaining() == 0:          # extensions block is optional (SSLv3 / old TLS)
        return order, data
    block = _Reader(r.vec(2))
    while block.remaining():
        ext_type = block.u16()
        body = block.vec(2)
        order.append(ext_type)
        data.setdefault(ext_type, body)
    return order, data


def parse_client_hello(body: bytes) -> ClientHello:
    r = _Reader(body)
    version = r.u16()
    r.take(32)                      # random
    r.vec(1)                        # session id
    ciphers = _u16_list(r.vec(2))
    r.vec(1)                        # compression methods
    exts, ext_data = _parse_extensions(r)
    ch = ClientHello(version, ciphers, exts, ext_data)

    # Sub-fields are decoded best-effort: a malformed optional extension should
    # not make the whole fingerprint disappear.
    try:
        if EXT_SERVER_NAME in ext_data:
            lst = _Reader(_Reader(ext_data[EXT_SERVER_NAME]).vec(2))
            while lst.remaining():
                name_type = lst.u8()
                name = lst.vec(2)
                if name_type == 0:
                    # SNI carries A-labels (punycode), i.e. plain ASCII on the wire.
                    ch.sni = name.decode("ascii", errors="replace")
                    break
    except (TLSParseError, UnicodeError):
        ch.sni = ch.sni or ""
    try:
        if EXT_SUPPORTED_GROUPS in ext_data:
            ch.supported_groups = _u16_list(_Reader(ext_data[EXT_SUPPORTED_GROUPS]).vec(2))
    except TLSParseError:
        pass
    try:
        if EXT_EC_POINT_FORMATS in ext_data:
            ch.ec_point_formats = list(_Reader(ext_data[EXT_EC_POINT_FORMATS]).vec(1))
    except TLSParseError:
        pass
    try:
        if EXT_SIGNATURE_ALGORITHMS in ext_data:
            ch.signature_algorithms = _u16_list(
                _Reader(ext_data[EXT_SIGNATURE_ALGORITHMS]).vec(2))
    except TLSParseError:
        pass
    try:
        if EXT_ALPN in ext_data:
            lst = _Reader(_Reader(ext_data[EXT_ALPN]).vec(2))
            while lst.remaining():
                ch.alpn.append(lst.vec(1))
    except TLSParseError:
        pass
    try:
        if EXT_SUPPORTED_VERSIONS in ext_data:
            ch.supported_versions = _u16_list(
                _Reader(ext_data[EXT_SUPPORTED_VERSIONS]).vec(1))
    except TLSParseError:
        pass
    return ch


def parse_server_hello(body: bytes) -> ServerHello:
    r = _Reader(body)
    version = r.u16()
    random = r.take(32)
    r.vec(1)                        # session id
    cipher = r.u16()
    r.u8()                          # compression method
    exts, ext_data = _parse_extensions(r)
    sh = ServerHello(version, cipher, exts, ext_data, is_hello_retry=(random == HRR_RANDOM))
    try:
        if EXT_SUPPORTED_VERSIONS in ext_data and len(ext_data[EXT_SUPPORTED_VERSIONS]) == 2:
            sh.selected_version = struct.unpack("!H", ext_data[EXT_SUPPORTED_VERSIONS])[0]
        if EXT_ALPN in ext_data:
            lst = _Reader(_Reader(ext_data[EXT_ALPN]).vec(2))
            if lst.remaining():
                sh.alpn = lst.vec(1)
    except TLSParseError:
        pass
    return sh


def extract_first_handshake(stream: bytes) -> tuple[int, bytes] | None:
    """Return (handshake_type, body) of the first handshake message in a TCP stream.

    Returns None if more bytes are needed. Raises TLSParseError if the stream
    does not start with TLS handshake records.
    """
    pos = 0
    hs = bytearray()
    while True:
        if len(stream) - pos < 5:
            return None
        rec_type, major, _minor, rec_len = struct.unpack("!BBBH", stream[pos:pos + 5])
        if rec_type != RECORD_HANDSHAKE or major != 3 or rec_len == 0 or rec_len > MAX_RECORD_LEN:
            raise TLSParseError("not a TLS handshake record")
        if len(stream) - pos - 5 < rec_len:
            # Record not complete yet, but we may already have the full message
            # if this is the last record we need; simplest is to wait.
            return None
        hs += stream[pos + 5:pos + 5 + rec_len]
        pos += 5 + rec_len
        if len(hs) >= 4:
            msg_type = hs[0]
            msg_len = int.from_bytes(hs[1:4], "big")
            if msg_type not in (HS_CLIENT_HELLO, HS_SERVER_HELLO):
                raise TLSParseError(f"first handshake message is type {msg_type}")
            if msg_len > MAX_HANDSHAKE_LEN:
                raise TLSParseError("handshake message too large")
            if len(hs) >= 4 + msg_len:
                return msg_type, bytes(hs[4:4 + msg_len])


def looks_like_tls_hello(payload: bytes) -> bool:
    """Cheap check on the first bytes of a TCP payload."""
    return (len(payload) >= 6 and payload[0] == RECORD_HANDSHAKE and payload[1] == 3
            and payload[5] in (HS_CLIENT_HELLO, HS_SERVER_HELLO))
