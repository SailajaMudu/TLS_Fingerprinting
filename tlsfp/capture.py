"""Packet sources (pcap file / live interface) built on Scapy + libpcap/Npcap."""
from __future__ import annotations

import logging
from collections.abc import Callable, Iterator

from .flows import FlowTracker, HelloEvent

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import IP, TCP, IPv6, PcapReader, PcapWriter, conf, sniff  # noqa: E402

SYN, FIN, RST = 0x02, 0x01, 0x04


def _decode(pkt):
    """Return (ts, flow, seq, syn, fin_or_rst, payload) or None for non-TCP."""
    if TCP not in pkt:
        return None
    if IP in pkt:
        ip = pkt[IP]
    elif IPv6 in pkt:
        ip = pkt[IPv6]
    else:
        return None
    tcp = pkt[TCP]
    flags = int(tcp.flags)
    payload = bytes(tcp.payload)
    if IP in pkt:
        # Trim Ethernet padding on short frames using the IP total length.
        tcp_len = ip.len - ip.ihl * 4 - tcp.dataofs * 4
        if 0 <= tcp_len < len(payload):
            payload = payload[:tcp_len]
    flow = (str(ip.src), int(tcp.sport), str(ip.dst), int(tcp.dport))
    return float(pkt.time), flow, int(tcp.seq), bool(flags & SYN), bool(flags & (FIN | RST)), payload


def events_from_packets(packets, tracker: FlowTracker | None = None) -> Iterator[HelloEvent]:
    tracker = tracker or FlowTracker()
    for pkt in packets:
        d = _decode(pkt)
        if d is None:
            continue
        ev = tracker.feed(*d)
        if ev is not None:
            yield ev


def events_from_pcap(path: str) -> Iterator[HelloEvent]:
    with PcapReader(path) as reader:          # handles pcap and pcapng
        yield from events_from_packets(reader)


def list_interfaces() -> list[tuple[str, str, str]]:
    rows = []
    for iface in conf.ifaces.values():
        ips = ", ".join(str(a) for a in (iface.ips.get(4, []) if hasattr(iface, "ips") else []))
        rows.append((iface.name, iface.description, ips))
    return rows


def sniff_live(on_event: Callable[[HelloEvent], None], iface: str | None = None,
               bpf: str = "tcp", write_pcap: str | None = None,
               timeout: float | None = None, count: int = 0) -> None:
    tracker = FlowTracker()
    writer = PcapWriter(write_pcap, append=False, sync=True) if write_pcap else None

    def handle(pkt):
        if writer is not None:
            writer.write(pkt)
        d = _decode(pkt)
        if d is None:
            return
        ev = tracker.feed(*d)
        if ev is not None:
            on_event(ev)

    try:
        sniff(iface=iface, filter=bpf, prn=handle, store=False, timeout=timeout, count=count)
    finally:
        if writer is not None:
            writer.close()


# ----------------------------------------------------- local process lookup

class ProcessResolver:
    """Map a local (ip, port) to the owning process via psutil (ground truth)."""

    def __init__(self):
        try:
            import psutil
        except ImportError as e:            # pragma: no cover
            raise RuntimeError("pip install psutil to use --resolve-process") from e
        self._psutil = psutil
        self._names: dict[int, str] = {}

    def lookup(self, flow) -> str | None:
        src, sport, _dst, _dport = flow
        try:
            conns = self._psutil.net_connections(kind="tcp")
        except Exception:                   # access denied etc.
            return None
        for c in conns:
            if c.laddr and c.laddr.port == sport and c.pid:
                return self._name(c.pid)
        return None

    def _name(self, pid: int) -> str:
        if pid not in self._names:
            try:
                self._names[pid] = self._psutil.Process(pid).name()
            except Exception:
                self._names[pid] = f"pid:{pid}"
        return self._names[pid]
