"""TCP stream reassembly (just enough to recover the first handshake message)
and ClientHello/ServerHello session pairing."""
from __future__ import annotations

from dataclasses import dataclass, field

from .fingerprints import (ClientFingerprint, ServerFingerprint,
                           client_fingerprint, server_fingerprint)
from .tls_parser import (HS_CLIENT_HELLO, ClientHello, ServerHello,
                         TLSParseError, extract_first_handshake,
                         looks_like_tls_hello, parse_client_hello,
                         parse_server_hello)

FlowKey = tuple[str, int, str, int]          # src, sport, dst, dport


@dataclass
class HelloEvent:
    ts: float
    flow: FlowKey
    is_client: bool
    hello: ClientHello | ServerHello
    fp: ClientFingerprint | ServerFingerprint

    @property
    def sni(self) -> str | None:
        return self.hello.sni if self.is_client else None


@dataclass
class Session:
    """A TLS connection: the ClientHello plus (once seen) the ServerHello."""
    client: HelloEvent
    server: HelloEvent | None = None
    process: str | None = None
    verdict: dict = field(default_factory=dict)

    @property
    def flow(self) -> FlowKey:
        return self.client.flow


@dataclass
class _Stream:
    base_seq: int | None = None
    segments: dict[int, bytes] = field(default_factory=dict)
    buffered: int = 0
    done: bool = False
    last_seen: float = 0.0


class FlowTracker:
    """Feed it TCP segments; it returns HelloEvents as soon as a hello is complete."""

    def __init__(self, max_bytes: int = 64 * 1024, idle_timeout: float = 120.0,
                 max_streams: int = 50_000):
        self.max_bytes = max_bytes
        self.idle_timeout = idle_timeout
        self.max_streams = max_streams
        self._streams: dict[FlowKey, _Stream] = {}
        self._fed = 0

    def feed(self, ts: float, flow: FlowKey, seq: int, syn: bool, fin_or_rst: bool,
             payload: bytes) -> HelloEvent | None:
        self._fed += 1
        if self._fed % 5000 == 0:
            self._expire(ts)

        st = self._streams.get(flow)
        if syn:
            # New connection on this 4-tuple: payload starts at ISN + 1.
            st = self._streams[flow] = _Stream(base_seq=(seq + 1) & 0xFFFFFFFF, last_seen=ts)
            return None
        if st is None:
            if not payload or not looks_like_tls_hello(payload):
                return None
            if len(self._streams) >= self.max_streams:
                self._expire(ts, force=True)
            st = self._streams[flow] = _Stream(base_seq=seq, last_seen=ts)
        st.last_seen = ts
        if st.done:
            if fin_or_rst:
                self._streams.pop(flow, None)
            return None
        if not payload:
            return None

        rel = (seq - st.base_seq) & 0xFFFFFFFF
        if rel >= self.max_bytes:          # before base (wrapped) or far beyond
            return None
        if len(payload) > len(st.segments.get(rel, b"")):
            st.buffered += len(payload) - len(st.segments.get(rel, b""))
            st.segments[rel] = payload

        data = self._contiguous(st)
        if not data:
            return None
        try:
            result = extract_first_handshake(data)
        except TLSParseError:
            self._finish(st)
            return None
        if result is None:
            if st.buffered > self.max_bytes:
                self._finish(st)
            return None

        self._finish(st)
        msg_type, body = result
        try:
            if msg_type == HS_CLIENT_HELLO:
                ch = parse_client_hello(body)
                return HelloEvent(ts, flow, True, ch, client_fingerprint(ch))
            sh = parse_server_hello(body)
            return HelloEvent(ts, flow, False, sh, server_fingerprint(sh))
        except TLSParseError:
            return None

    @staticmethod
    def _contiguous(st: _Stream) -> bytes:
        out = bytearray()
        offset = 0
        while True:
            # find any segment covering `offset`
            best = None
            for rel, seg in st.segments.items():
                if rel <= offset < rel + len(seg):
                    if best is None or rel + len(seg) > best[0] + len(best[1]):
                        best = (rel, seg)
            if best is None:
                return bytes(out)
            rel, seg = best
            out += seg[offset - rel:]
            offset = rel + len(seg)

    @staticmethod
    def _finish(st: _Stream) -> None:
        st.done = True
        st.segments.clear()
        st.buffered = 0

    def _expire(self, now: float, force: bool = False) -> None:
        cutoff = now - (self.idle_timeout / 4 if force else self.idle_timeout)
        for k in [k for k, s in self._streams.items() if s.last_seen < cutoff]:
            del self._streams[k]


class SessionTable:
    """Pairs ServerHellos with the ClientHello of the reverse flow."""

    def __init__(self, max_pending: int = 50_000):
        self._pending: dict[FlowKey, Session] = {}
        self.max_pending = max_pending

    def add(self, ev: HelloEvent) -> tuple[Session | None, bool]:
        """Returns (session, is_new). is_new=False means a ServerHello completed it."""
        if ev.is_client:
            if len(self._pending) >= self.max_pending:
                self._pending.pop(next(iter(self._pending)))
            s = Session(client=ev)
            self._pending[ev.flow] = s
            return s, True
        src, sport, dst, dport = ev.flow
        s = self._pending.pop((dst, dport, src, sport), None)
        if s is None:
            return None, False
        s.server = ev
        return s, False

    def unanswered(self) -> list[Session]:
        return list(self._pending.values())
