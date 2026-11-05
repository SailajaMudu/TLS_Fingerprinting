"""Cross-check our fingerprints against Wireshark/tshark's independent JA3/JA3S/JA4
implementation (tshark >= 4.2 exposes tls.handshake.ja3 / ja3s / ja4 / ja4_r).

Known tshark discrepancy: recent Chrome/Edge put a GREASE value into the
signature_algorithms list. The JA4 spec says GREASE is ignored everywhere, but
tshark 4.6 keeps it in the sigalg part, so its JA4 changes on every connection.
Such cases are reported separately as "match except tshark GREASE-in-sigalgs".
"""
from __future__ import annotations

import os
import shutil
import subprocess

from .capture import events_from_pcap
from .tls_parser import is_grease

_FIELDS = ["ip.src", "ipv6.src", "tcp.srcport", "ip.dst", "ipv6.dst", "tcp.dstport",
           "tls.handshake.type", "tls.handshake.ja3", "tls.handshake.ja3s",
           "tls.handshake.ja4", "tls.handshake.ja4_r"]


def find_tshark() -> str | None:
    found = shutil.which("tshark")
    if found:
        return found
    for p in (r"C:\Program Files\Wireshark\tshark.exe",
              "/usr/bin/tshark", "/usr/local/bin/tshark",
              "/Applications/Wireshark.app/Contents/MacOS/tshark"):
        if os.path.exists(p):
            return p
    return None


def tshark_fingerprints(pcap: str, tshark: str) -> dict[tuple, dict]:
    if not os.path.exists(pcap):
        raise FileNotFoundError(pcap)
    cmd = [tshark, "-r", pcap, "-n", "-Y", "tls.handshake.type == 1 || tls.handshake.type == 2",
           "-T", "fields", "-E", "separator=\t", "-E", "occurrence=f"]
    for f in _FIELDS:
        cmd += ["-e", f]
    out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    result: dict[tuple, dict] = {}
    for line in out.splitlines():
        cols = (line.split("\t") + [""] * len(_FIELDS))[:len(_FIELDS)]
        src = cols[0] or cols[1]
        dst = cols[3] or cols[4]
        if not cols[2] or not cols[5]:
            continue
        flow = (src, int(cols[2]), dst, int(cols[5]))
        is_client = cols[6].split(",")[0] == "1"
        key = (flow, is_client)
        if key in result:            # keep the first hello (ignore post-HRR ClientHello)
            continue
        result[key] = ({"ja3": cols[7], "ja4": cols[9], "ja4_r": cols[10]} if is_client
                       else {"ja3s": cols[8]})
    return result


def _strip_grease_ja4_r(ja4_r: str) -> str:
    parts = ja4_r.split("_")
    if len(parts) == 4:
        parts[3] = ",".join(x for x in parts[3].split(",")
                            if x and not is_grease(int(x, 16)))
    return "_".join(parts)


def validate(pcap: str, tshark: str | None = None) -> dict:
    tshark = tshark or find_tshark()
    if not tshark:
        raise RuntimeError("tshark not found; install Wireshark >= 4.2")
    ref = tshark_fingerprints(pcap, tshark)
    stats = {"ja3": [0, 0], "ja4": [0, 0], "ja3s": [0, 0], "ja4_grease_sigalg": 0,
             "only_ours": 0, "only_tshark": 0}
    mismatches = []
    seen = set()
    for ev in events_from_pcap(pcap):
        key = (ev.flow, ev.is_client)
        seen.add(key)
        theirs = ref.get(key)
        if theirs is None:
            stats["only_ours"] += 1
            continue
        ours = ({"ja3": ev.fp.ja3, "ja4": ev.fp.ja4} if ev.is_client else {"ja3s": ev.fp.ja3s})
        for k, v in ours.items():
            if not theirs.get(k):
                continue
            stats[k][1] += 1
            if theirs[k] == v:
                stats[k][0] += 1
            elif k == "ja4" and _strip_grease_ja4_r(theirs["ja4_r"]) == ev.fp.ja4_r:
                stats["ja4_grease_sigalg"] += 1
            else:
                raw = ev.fp.ja4_r if k == "ja4" else ev.fp.ja3_full if k == "ja3" else ev.fp.ja3s_full
                mismatches.append((ev.flow, k, v, theirs[k], raw, theirs.get("ja4_r", "")))
    stats["only_tshark"] = len(set(ref) - seen)
    return {"stats": stats, "mismatches": mismatches}
