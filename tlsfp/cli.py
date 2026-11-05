"""Command-line interface:  python -m tlsfp <command> ..."""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import defaultdict
from datetime import datetime

from .db import KINDS, FingerprintDB
from .flows import HelloEvent, Session, SessionTable

RED, GREEN, YELLOW, DIM, RESET = "\033[31m", "\033[32m", "\033[33m", "\033[2m", "\033[0m"


def _color(enabled: bool):
    return (lambda c, s: f"{c}{s}{RESET}") if enabled else (lambda c, s: s)


def _ts(t: float) -> str:
    return datetime.fromtimestamp(t).strftime("%H:%M:%S.%f")[:-3]


# ------------------------------------------------------------------ pipeline

class Pipeline:
    """events -> sessions -> identification -> output/DB."""

    def __init__(self, db: FingerprintDB, args, resolver=None):
        self.db = db
        self.args = args
        self.sessions = SessionTable()
        self.resolver = resolver
        self.c = _color(sys.stdout.isatty() and not getattr(args, "json", False))
        self.results: list[Session] = []

    def on_event(self, ev: HelloEvent) -> None:
        sess, is_new = self.sessions.add(ev)
        if sess is None:
            return
        if is_new:
            if self.resolver:
                sess.process = self.resolver.lookup(ev.flow)
            m = self.db.identify(ev.fp.ja4, ev.fp.ja3)
            sess.verdict = {"client": m}
            if getattr(self.args, "sni", None) and self.args.sni not in (ev.sni or ""):
                return
            self.results.append(sess)
            if not getattr(self.args, "no_record", False):
                self.db.record(sess, m)
            if getattr(self.args, "auto_learn", False) and sess.process:
                self.db.add("ja4", ev.fp.ja4, sess.process, "process", "auto-learn", ev.fp.ja4_r)
                self.db.add("ja3", ev.fp.ja3, sess.process, "process", "auto-learn", ev.fp.ja3_full)
            self.print_client(sess)
        else:
            sm = self.db.identify(ev.fp.ja4s, ev.fp.ja3s, client=False)
            sess.verdict["server"] = sm
            if not getattr(self.args, "no_record", False):
                self.db.conn.execute(
                    "UPDATE observations SET ja3s=?, ja4s=? WHERE src=? AND sport=? AND dst=? "
                    "AND dport=? AND ts=?",
                    (ev.fp.ja3s, ev.fp.ja4s, *sess.flow, sess.client.ts))
                self.db.conn.commit()
            if getattr(self.args, "show_server", False):
                self.print_server(sess)

    def print_client(self, s: Session) -> None:
        ev, m = s.client, s.verdict["client"]
        if getattr(self.args, "json", False):
            print(json.dumps({
                "ts": ev.ts, "src": ev.flow[0], "sport": ev.flow[1], "dst": ev.flow[2],
                "dport": ev.flow[3], "sni": ev.sni, "ja3": ev.fp.ja3, "ja3_full": ev.fp.ja3_full,
                "ja4": ev.fp.ja4, "ja4_r": ev.fp.ja4_r, "process": s.process,
                "verdict": m.label, "category": m.category, "matched_on": m.matched_on}),
                flush=True)
            return
        c = self.c
        if m.category == "malware":
            verdict = c(RED, f"!! {m.label} [{m.category}]")
        elif m.labels:
            verdict = c(YELLOW if m.ambiguous else GREEN, f"{m.label}") + c(DIM, f" via {m.matched_on}")
        else:
            verdict = c(DIM, "UNKNOWN")
        proc = f"  proc={s.process}" if s.process else ""
        print(f"{_ts(ev.ts)} CH {ev.flow[0]}:{ev.flow[1]} -> {ev.flow[2]}:{ev.flow[3]} "
              f"sni={ev.sni or '-'}{proc}\n"
              f"    JA3 {ev.fp.ja3}   JA4 {ev.fp.ja4}\n    => {verdict}", flush=True)
        if getattr(self.args, "verbose", False):
            print(c(DIM, f"    ja3_full {ev.fp.ja3_full}\n    ja4_r    {ev.fp.ja4_r}"))

    def print_server(self, s: Session) -> None:
        ev = s.server
        if getattr(self.args, "json", False):
            print(json.dumps({"ts": ev.ts, "server_for": list(s.flow), "ja3s": ev.fp.ja3s,
                              "ja3s_full": ev.fp.ja3s_full, "ja4s": ev.fp.ja4s}), flush=True)
            return
        sm = s.verdict.get("server")
        lab = f" => {sm.label}" if sm and sm.labels else ""
        print(f"{_ts(ev.ts)} SH {ev.flow[0]}:{ev.flow[1]} -> {ev.flow[2]}:{ev.flow[3]}\n"
              f"    JA3S {ev.fp.ja3s}   JA4S {ev.fp.ja4s}{lab}", flush=True)


# ------------------------------------------------------------------ commands

def cmd_ifaces(args) -> None:
    from .capture import list_interfaces
    for name, desc, ips in list_interfaces():
        print(f"{name:40.40}  {desc:45.45}  {ips}")


def cmd_live(args) -> None:
    from .capture import ProcessResolver, sniff_live
    db = FingerprintDB(args.db, args.redis)
    resolver = ProcessResolver() if args.resolve_process or args.auto_learn else None
    p = Pipeline(db, args, resolver)
    print(f"[*] capturing on {args.iface or 'default interface'} filter='{args.filter}' "
          f"(Ctrl+C to stop)", file=sys.stderr)
    try:
        sniff_live(p.on_event, iface=args.iface, bpf=args.filter, write_pcap=args.write,
                   timeout=args.timeout)
    except KeyboardInterrupt:
        pass
    print(f"[*] {len(p.results)} TLS sessions seen", file=sys.stderr)


def cmd_analyze(args) -> None:
    from .capture import events_from_pcap
    db = FingerprintDB(args.db, args.redis)
    args.no_record = not args.record
    p = Pipeline(db, args)
    for ev in events_from_pcap(args.pcap):
        p.on_event(ev)
    if not args.json:
        _summary(p.results)


def _summary(sessions: list[Session]) -> None:
    by = defaultdict(lambda: [0, set(), set()])
    for s in sessions:
        m = s.verdict["client"]
        row = by[m.label]
        row[0] += 1
        row[1].add(s.client.fp.ja3)
        row[2].add(s.client.fp.ja4)
    print("\n=== Summary ===")
    print(f"{'verdict':45} {'sessions':>8} {'#JA3':>5} {'#JA4':>5}")
    for label, (n, j3, j4) in sorted(by.items(), key=lambda x: -x[1][0]):
        print(f"{label[:45]:45} {n:8} {len(j3):5} {len(j4):5}")


def _load_manifest(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return json.load(f)["runs"]


def _match_manifest(ev: HelloEvent, runs: list[dict], slack: float) -> dict | None:
    for r in runs:
        if r["start"] - slack <= ev.ts <= r["end"] + slack:
            sni = r.get("sni")
            if sni and (ev.sni or "") != sni:
                continue
            return r
    return None


def cmd_learn(args) -> None:
    """Label the ClientHellos in a pcap and store them as reference fingerprints."""
    from .capture import events_from_pcap
    db = FingerprintDB(args.db)
    runs = _load_manifest(args.manifest) if args.manifest else None
    if runs is None and not args.label:
        sys.exit("learn: give --label or --manifest")
    learned = defaultdict(lambda: {"ja3": set(), "ja4": set(), "n": 0, "cat": "unknown"})
    for ev in events_from_pcap(args.pcap):
        if not ev.is_client:
            continue
        if runs is not None:
            r = _match_manifest(ev, runs, args.slack)
            if r is None:
                continue
            label, cat = r["label"], r.get("category", "unknown")
        else:
            if args.sni and args.sni not in (ev.sni or ""):
                continue
            label, cat = args.label, args.category
        info = learned[label]
        info["n"] += 1
        info["cat"] = cat
        info["ja3"].add((ev.fp.ja3, ev.fp.ja3_full))
        info["ja4"].add((ev.fp.ja4, ev.fp.ja4_r))
    for label, info in learned.items():
        for v, raw in info["ja4"]:
            db.add("ja4", v, label, info["cat"], "learned", raw)
        if not args.ja4_only:
            for v, raw in info["ja3"]:
                db.add("ja3", v, label, info["cat"], "learned", raw)
    _stability_table(learned)


def _stability_table(learned) -> None:
    print(f"{'label':40} {'hellos':>6} {'#JA3':>5} {'#JA4':>5}  note")
    for label, info in sorted(learned.items()):
        n3, n4 = len(info["ja3"]), len(info["ja4"])
        note = ""
        if n3 > 1 and n4 == 1:
            note = "JA3 unstable (extension-order randomisation), JA4 stable"
        elif n3 > 1 or n4 > 1:
            note = "multiple fingerprints"
        print(f"{label[:40]:40} {info['n']:6} {n3:5} {n4:5}  {note}")
    if not learned:
        print("(no matching ClientHellos - check manifest times / --sni / interface)")


def cmd_stability(args) -> None:
    from .capture import events_from_pcap
    runs = _load_manifest(args.manifest)
    learned = defaultdict(lambda: {"ja3": set(), "ja4": set(), "n": 0})
    for ev in events_from_pcap(args.pcap):
        if ev.is_client and (r := _match_manifest(ev, runs, args.slack)):
            info = learned[r["label"]]
            info["n"] += 1
            info["ja3"].add(ev.fp.ja3)
            info["ja4"].add(ev.fp.ja4)
    _stability_table(learned)


def cmd_evaluate(args) -> None:
    """Accuracy of identification against a labelled (manifest) test capture."""
    from .capture import events_from_pcap
    db = FingerprintDB(args.db)
    runs = _load_manifest(args.manifest)
    rows = defaultdict(lambda: defaultdict(int))
    correct = total = 0
    for ev in events_from_pcap(args.pcap):
        if not ev.is_client or not (r := _match_manifest(ev, runs, args.slack)):
            continue
        m = db.identify(None if args.ja3_only else ev.fp.ja4, None if args.ja4_only else ev.fp.ja3)
        truth = r["label"]
        rows[truth][m.label] += 1
        total += 1
        correct += (m.labels == [truth])
    print(f"{'ground truth':38} -> predicted (count)")
    for truth, preds in sorted(rows.items()):
        print(f"{truth[:38]:38} -> " + ", ".join(f"{p} ({n})" for p, n in
                                                 sorted(preds.items(), key=lambda x: -x[1])))
    if total:
        print(f"\nexact-match accuracy: {correct}/{total} = {100 * correct / total:.1f}%  "
              f"(using {'JA3' if args.ja3_only else 'JA4' if args.ja4_only else 'JA4 then JA3'})")


def cmd_validate(args) -> None:
    from .validate import validate
    res = validate(args.pcap, args.tshark)
    st = res["stats"]
    print("Cross-check against Wireshark/tshark built-in fingerprints")
    for k in ("ja3", "ja3s", "ja4"):
        ok, n = st[k]
        pct = f"{100 * ok / n:.1f}%" if n else "n/a"
        print(f"  {k.upper():5} {ok:5}/{n:<5} match  ({pct})")
    if st["ja4_grease_sigalg"]:
        print(f"        + {st['ja4_grease_sigalg']} JA4 identical once tshark's GREASE value in the "
              f"signature_algorithms list is removed\n"
              f"          (JA4 spec ignores GREASE; tshark keeps it, so its JA4 for Chrome/Edge "
              f"changes every connection)")
    print(f"  hellos only we parsed: {st['only_ours']}   only tshark parsed: {st['only_tshark']}")
    for flow, k, ours, theirs, raw, theirs_raw in res["mismatches"][:20]:
        print(f"  MISMATCH {k} {flow}: ours={ours} tshark={theirs}\n"
              f"           ours_raw={raw}\n           tshark_r={theirs_raw}")
    if res["mismatches"]:
        sys.exit(1)


def cmd_db(args) -> None:
    db = FingerprintDB(args.db)
    if args.db_cmd == "list":
        rows = db.entries(args.kind)
        for r in rows:
            print(f"{r['kind']:5} {r['value']:40} {r['label'][:40]:40} {r['category']:10} "
                  f"{r['source']}")
        print(f"({len(rows)} entries)")
    elif args.db_cmd == "add":
        db.add(args.kind, args.value, args.label, args.category, "manual", notes=args.notes)
        print("added")
    elif args.db_cmd == "remove":
        print(f"removed {db.remove(args.kind, args.value, args.label)}")
    elif args.db_cmd == "export":
        print(f"exported {db.export_json(args.file)} entries -> {args.file}")
    elif args.db_cmd == "import":
        print(f"imported {db.import_json(args.file)} entries")
    elif args.db_cmd == "import-sslbl":
        print(f"imported {db.import_sslbl(args.file)} malware JA3 entries from SSLBL")
    elif args.db_cmd == "import-csv":
        print(f"imported {db.import_csv(args.file, args.category)} entries")
    elif args.db_cmd == "sync-redis":
        print(f"pushed {db.sync_redis(args.url)} entries to {args.url}")


def cmd_report(args) -> None:
    db = FingerprintDB(args.db)
    since = time.time() - args.hours * 3600 if args.hours else None
    rep = db.report(since)
    print(f"Observations: {rep['total']}\n\nBy verdict:")
    for r in rep["by_verdict"]:
        print(f"  {r['n']:6}  {r['verdict'][:50]:50} [{r['category']}]")
    print("\nTop unknown fingerprints (candidates to label):")
    for r in rep["top_unknown"]:
        print(f"  {r['n']:6}  {r['ja4']}  {r['ja3']}\n          sni={(r['snis'] or '')[:80]}"
              f"  procs={r['procs'] or '-'}")
    if rep["process_vs_verdict"]:
        print("\nProcess (ground truth) vs fingerprint verdict:")
        for r in rep["process_vs_verdict"]:
            print(f"  {r['process'][:30]:30} -> {r['verdict'][:50]:50} {r['n']}")
    if rep["malware"]:
        print("\n!! Malware fingerprint hits:")
        for r in rep["malware"]:
            print(f"  {_ts(r['ts'])} {r['src']} -> {r['dst']}:{r['dport']} sni={r['sni']} "
                  f"{r['verdict']} ({r['ja3']})")


# ------------------------------------------------------------------ argparse

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="tlsfp", description="Passive TLS JA3/JA3S/JA4/JA4S fingerprinting")
    p.add_argument("--db", default="tlsfp.db", help="SQLite database (default tlsfp.db)")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("ifaces", help="list capture interfaces").set_defaults(func=cmd_ifaces)

    def common_out(sp):
        sp.add_argument("--json", action="store_true", help="JSON lines output")
        sp.add_argument("-v", "--verbose", action="store_true", help="show raw JA3/JA4 strings")
        sp.add_argument("--show-server", action="store_true", help="also print ServerHello JA3S/JA4S")
        sp.add_argument("--sni", help="only show handshakes whose SNI contains this")
        sp.add_argument("--redis", help="use Redis/Valkey for lookups, e.g. redis://localhost:6379/0")

    sp = sub.add_parser("live", help="capture from an interface")
    sp.add_argument("-i", "--iface")
    sp.add_argument("-f", "--filter", default="tcp", help="BPF filter (default 'tcp': any port)")
    sp.add_argument("-w", "--write", help="also save packets to this pcap")
    sp.add_argument("-t", "--timeout", type=float)
    sp.add_argument("--resolve-process", action="store_true",
                    help="attribute local connections to processes (ground truth)")
    sp.add_argument("--auto-learn", action="store_true",
                    help="store fingerprints labelled with the process name")
    sp.add_argument("--no-record", action="store_true",
                    help="do not store observations in the DB")
    common_out(sp)
    sp.set_defaults(func=cmd_live)

    sp = sub.add_parser("analyze", help="fingerprint a pcap/pcapng file")
    sp.add_argument("pcap")
    sp.add_argument("--record", action="store_true", help="store observations in the DB")
    common_out(sp)
    sp.set_defaults(func=cmd_analyze)

    sp = sub.add_parser("learn", help="add labelled fingerprints from a pcap to the DB")
    sp.add_argument("pcap")
    sp.add_argument("--manifest", help="manifest.json written by scripts/gen_traffic.py")
    sp.add_argument("--label")
    sp.add_argument("--category", default="unknown")
    sp.add_argument("--sni")
    sp.add_argument("--slack", type=float, default=1.0, help="seconds of slack on manifest windows")
    sp.add_argument("--ja4-only", action="store_true")
    sp.set_defaults(func=cmd_learn)

    sp = sub.add_parser("stability", help="distinct JA3 vs JA4 per client in a labelled pcap")
    sp.add_argument("pcap")
    sp.add_argument("--manifest", required=True)
    sp.add_argument("--slack", type=float, default=1.0)
    sp.set_defaults(func=cmd_stability)

    sp = sub.add_parser("evaluate", help="identification accuracy on a labelled test pcap")
    sp.add_argument("pcap")
    sp.add_argument("--manifest", required=True)
    sp.add_argument("--slack", type=float, default=1.0)
    g = sp.add_mutually_exclusive_group()
    g.add_argument("--ja3-only", action="store_true")
    g.add_argument("--ja4-only", action="store_true")
    sp.set_defaults(func=cmd_evaluate)

    sp = sub.add_parser("validate", help="cross-check against tshark's JA3/JA3S/JA4")
    sp.add_argument("pcap")
    sp.add_argument("--tshark")
    sp.set_defaults(func=cmd_validate)

    sp = sub.add_parser("report", help="historical report from recorded observations")
    sp.add_argument("--hours", type=float, help="only the last N hours")
    sp.set_defaults(func=cmd_report)

    dbp = sub.add_parser("db", help="manage the reference database")
    dsub = dbp.add_subparsers(dest="db_cmd", required=True)
    s = dsub.add_parser("list")
    s.add_argument("--kind", choices=KINDS)
    s = dsub.add_parser("add")
    s.add_argument("kind", choices=KINDS)
    s.add_argument("value")
    s.add_argument("label")
    s.add_argument("--category", default="unknown")
    s.add_argument("--notes")
    s = dsub.add_parser("remove")
    s.add_argument("kind", choices=KINDS)
    s.add_argument("value")
    s.add_argument("--label")
    for name in ("export", "import", "import-sslbl"):
        dsub.add_parser(name).add_argument("file")
    s = dsub.add_parser("import-csv")
    s.add_argument("file")
    s.add_argument("--category", default="unknown")
    dsub.add_parser("sync-redis").add_argument("url")
    dbp.set_defaults(func=cmd_db)
    return p


def main(argv=None) -> None:
    if sys.platform == "win32":
        import os
        os.system("")                     # enable ANSI colours in Windows consoles
    args = build_parser().parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
