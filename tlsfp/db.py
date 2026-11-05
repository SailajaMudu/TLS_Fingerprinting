"""Reference fingerprint database (SQLite) with an optional Redis/Valkey KV mirror.

fingerprints : curated reference entries  (kind, value) -> label/category
observations : every handshake seen, for historical reporting
"""
from __future__ import annotations

import csv
import json
import sqlite3
import time
from dataclasses import dataclass

KINDS = ("ja3", "ja3s", "ja4", "ja4s")

SCHEMA = """
CREATE TABLE IF NOT EXISTS fingerprints (
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    label TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT 'unknown',
    source TEXT NOT NULL DEFAULT 'learned',
    raw TEXT,
    notes TEXT,
    first_seen REAL,
    last_seen REAL,
    hits INTEGER NOT NULL DEFAULT 0,
    UNIQUE(kind, value, label)
);
CREATE INDEX IF NOT EXISTS idx_fp_lookup ON fingerprints(kind, value);
CREATE TABLE IF NOT EXISTS observations (
    id INTEGER PRIMARY KEY,
    ts REAL, src TEXT, sport INTEGER, dst TEXT, dport INTEGER, sni TEXT,
    ja3 TEXT, ja4 TEXT, ja3s TEXT, ja4s TEXT,
    process TEXT, verdict TEXT, matched_on TEXT, category TEXT
);
CREATE INDEX IF NOT EXISTS idx_obs_ts ON observations(ts);
"""


@dataclass
class Match:
    labels: list[str]
    categories: list[str]
    matched_on: str          # "ja4", "ja3", "ja4+ja3", or "" when unknown

    @property
    def label(self) -> str:
        return " | ".join(self.labels) if self.labels else "UNKNOWN"

    @property
    def category(self) -> str:
        if "malware" in self.categories:
            return "malware"
        return self.categories[0] if self.categories else "unknown"

    @property
    def ambiguous(self) -> bool:
        return len(self.labels) > 1


class FingerprintDB:
    def __init__(self, path: str = "tlsfp.db", redis_url: str | None = None):
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.redis = None
        if redis_url:
            import redis  # optional dependency
            self.redis = redis.Redis.from_url(redis_url, decode_responses=True)

    # ------------------------------------------------------------ reference data
    def add(self, kind: str, value: str, label: str, category: str = "unknown",
            source: str = "learned", raw: str | None = None, notes: str | None = None) -> bool:
        if kind not in KINDS:
            raise ValueError(f"kind must be one of {KINDS}")
        now = time.time()
        cur = self.conn.execute(
            """INSERT INTO fingerprints(kind, value, label, category, source, raw, notes,
                                        first_seen, last_seen, hits)
               VALUES (?,?,?,?,?,?,?,?,?,1)
               ON CONFLICT(kind, value, label) DO UPDATE SET
                   last_seen=excluded.last_seen, hits=hits+1,
                   raw=COALESCE(fingerprints.raw, excluded.raw)""",
            (kind, value, label, category, source, raw, notes, now, now))
        self.conn.commit()
        return cur.rowcount > 0

    def remove(self, kind: str, value: str, label: str | None = None) -> int:
        q, args = "DELETE FROM fingerprints WHERE kind=? AND value=?", [kind, value]
        if label:
            q += " AND label=?"
            args.append(label)
        n = self.conn.execute(q, args).rowcount
        self.conn.commit()
        return n

    def entries(self, kind: str | None = None) -> list[sqlite3.Row]:
        if kind:
            return self.conn.execute(
                "SELECT * FROM fingerprints WHERE kind=? ORDER BY label", (kind,)).fetchall()
        return self.conn.execute("SELECT * FROM fingerprints ORDER BY label, kind").fetchall()

    def _lookup(self, kind: str, value: str) -> list[tuple[str, str]]:
        if not value:
            return []
        if self.redis is not None:
            members = self.redis.smembers(f"tlsfp:{kind}:{value}")
            return [tuple(m.split("\x1f", 1)) for m in members]  # type: ignore[misc]
        rows = self.conn.execute(
            "SELECT label, category FROM fingerprints WHERE kind=? AND value=?",
            (kind, value)).fetchall()
        return [(r["label"], r["category"]) for r in rows]

    def identify(self, ja4: str | None, ja3: str | None, client: bool = True) -> Match:
        """JA4 is preferred (stable under extension-order randomisation); JA3 is fallback.
        If both match, the intersection of labels is used when non-empty."""
        k4, k3 = ("ja4", "ja3") if client else ("ja4s", "ja3s")
        m4 = dict(self._lookup(k4, ja4 or ""))
        m3 = dict(self._lookup(k3, ja3 or ""))
        if m4 and m3 and set(m4) & set(m3):
            both = sorted(set(m4) & set(m3))
            return Match(both, [m4[l] for l in both], f"{k4}+{k3}")
        if m4:
            return Match(sorted(m4), [m4[l] for l in sorted(m4)], k4)
        if m3:
            return Match(sorted(m3), [m3[l] for l in sorted(m3)], k3)
        return Match([], [], "")

    # ------------------------------------------------------------ observations
    def record(self, session, verdict: Match) -> None:
        c = session.client
        s = session.server
        src, sport, dst, dport = c.flow
        self.conn.execute(
            """INSERT INTO observations(ts, src, sport, dst, dport, sni, ja3, ja4, ja3s, ja4s,
                                        process, verdict, matched_on, category)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (c.ts, src, sport, dst, dport, c.sni, c.fp.ja3, c.fp.ja4,
             s.fp.ja3s if s else None, s.fp.ja4s if s else None,
             session.process, verdict.label, verdict.matched_on, verdict.category))
        self.conn.commit()

    # ------------------------------------------------------------ import/export
    def export_json(self, path: str) -> int:
        rows = [{k: r[k] for k in ("kind", "value", "label", "category", "source", "raw", "notes")}
                for r in self.entries()]
        with open(path, "w", encoding="utf-8") as f:
            json.dump(rows, f, indent=2)
        return len(rows)

    def import_json(self, path: str) -> int:
        with open(path, encoding="utf-8") as f:
            rows = json.load(f)
        for r in rows:
            self.add(r["kind"], r["value"], r["label"], r.get("category", "unknown"),
                     r.get("source", "imported"), r.get("raw"), r.get("notes"))
        return len(rows)

    def import_sslbl(self, path: str) -> int:
        """abuse.ch SSLBL JA3 blacklist: https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv
        Format: ja3_md5,Firstseen,Lastseen,Listingreason"""
        n = 0
        with open(path, encoding="utf-8") as f:
            for line in f:
                if not line.strip() or line.startswith("#"):
                    continue
                parts = [p.strip() for p in line.split(",")]
                if len(parts) < 4 or len(parts[0]) != 32:
                    continue
                self.add("ja3", parts[0], parts[3], "malware", "abuse.ch SSLBL",
                         notes=f"first {parts[1]} last {parts[2]}")
                n += 1
        return n

    def import_csv(self, path: str, default_category: str = "unknown",
                   source: str = "csv") -> int:
        """Generic CSV with columns kind,value,label[,category,notes]  OR the FoxIO
        ja4plus-mapping.csv (columns Application/Library/... ja4, ja4s ...)."""
        n = 0
        with open(path, encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            cols = {c.lower().strip(): c for c in (reader.fieldnames or [])}
            for row in reader:
                if "kind" in cols and "value" in cols:
                    self.add(row[cols["kind"]].strip(), row[cols["value"]].strip(),
                             row[cols["label"]].strip(),
                             (row.get(cols.get("category", ""), "") or default_category).strip(),
                             source, notes=row.get(cols.get("notes", ""), None))
                    n += 1
                    continue
                label = " / ".join(
                    row[cols[c]].strip() for c in ("application", "library", "device", "os")
                    if c in cols and row[cols[c]] and row[cols[c]].strip())
                if not label:
                    continue
                for kind in ("ja4", "ja4s", "ja3", "ja3s"):
                    if kind in cols and row[cols[kind]] and row[cols[kind]].strip():
                        cat = "malware" if any(w in label.lower() for w in
                                               ("malware", "c2", "rat", "stealer", "cobalt",
                                                "sliver", "trojan")) else default_category
                        self.add(kind, row[cols[kind]].strip(), label, cat, source)
                        n += 1
        return n

    def sync_redis(self, redis_url: str) -> int:
        import redis
        r = redis.Redis.from_url(redis_url, decode_responses=True)
        pipe = r.pipeline()
        for k in r.scan_iter("tlsfp:*"):
            pipe.delete(k)
        rows = self.entries()
        for row in rows:
            pipe.sadd(f"tlsfp:{row['kind']}:{row['value']}",
                      f"{row['label']}\x1f{row['category']}")
        pipe.execute()
        return len(rows)

    # ------------------------------------------------------------ reporting
    def report(self, since: float | None = None) -> dict:
        where, args = ("WHERE ts >= ?", [since]) if since else ("", [])
        q = lambda sql: self.conn.execute(sql.format(where=where), args).fetchall()  # noqa: E731
        return {
            "total": q("SELECT COUNT(*) n FROM observations {where}")[0]["n"],
            "by_verdict": q("""SELECT verdict, category, COUNT(*) n FROM observations {where}
                               GROUP BY verdict, category ORDER BY n DESC"""),
            "top_unknown": q("""SELECT ja4, ja3, COUNT(*) n, GROUP_CONCAT(DISTINCT sni) snis,
                                       GROUP_CONCAT(DISTINCT process) procs
                                FROM observations {where}
                                {and_} verdict='UNKNOWN'
                                GROUP BY ja4, ja3 ORDER BY n DESC LIMIT 10"""
                             .replace("{and_}", "AND" if where else "WHERE")),
            "malware": q("""SELECT ts, src, dst, dport, sni, verdict, ja3 FROM observations
                            {where} {and_} category='malware' ORDER BY ts DESC LIMIT 50"""
                         .replace("{and_}", "AND" if where else "WHERE")),
            "process_vs_verdict": q("""SELECT process, verdict, COUNT(*) n FROM observations
                                       {where} {and_} process IS NOT NULL
                                       GROUP BY process, verdict ORDER BY process, n DESC"""
                                    .replace("{and_}", "AND" if where else "WHERE")),
        }
