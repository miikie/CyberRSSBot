from __future__ import annotations

import asyncio
import json
import logging
import os
import time

import aiosqlite

from .util import parse_claim

log = logging.getLogger(__name__)

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS seen (key TEXT PRIMARY KEY, source TEXT, ts INTEGER);
CREATE TABLE IF NOT EXISTS http_cache (key TEXT PRIMARY KEY, etag TEXT, last_modified TEXT);
CREATE TABLE IF NOT EXISTS sources (
    id TEXT PRIMARY KEY, last_ok INTEGER, last_err TEXT, last_err_ts INTEGER,
    fails INTEGER DEFAULT 0, seeded INTEGER DEFAULT 0, items INTEGER DEFAULT 0, cursor TEXT);
CREATE TABLE IF NOT EXISTS vulns (
    vid TEXT PRIMARY KEY, data TEXT NOT NULL, posted INTEGER DEFAULT 0,
    channel_id INTEGER, message_id INTEGER, dirty INTEGER DEFAULT 0,
    first_seen INTEGER, updated INTEGER);
CREATE TABLE IF NOT EXISTS aliases (alias TEXT PRIMARY KEY, vid TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS stories (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, tokens TEXT, cves TEXT,
    data TEXT NOT NULL, channel_id INTEGER, message_id INTEGER, dirty INTEGER DEFAULT 0);
CREATE INDEX IF NOT EXISTS idx_stories_ts ON stories(ts);
CREATE INDEX IF NOT EXISTS idx_stories_dirty ON stories(dirty);
CREATE INDEX IF NOT EXISTS idx_vulns_dirty ON vulns(dirty);
CREATE INDEX IF NOT EXISTS idx_vulns_first_seen ON vulns(first_seen);
CREATE TABLE IF NOT EXISTS fin_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, tickers TEXT, event TEXT, tokens TEXT,
    data TEXT NOT NULL, channel_id INTEGER, message_id INTEGER, dirty INTEGER DEFAULT 0);
CREATE INDEX IF NOT EXISTS idx_fin_items_ts ON fin_items(ts);
CREATE INDEX IF NOT EXISTS idx_fin_items_dirty ON fin_items(dirty);
CREATE TABLE IF NOT EXISTS fin_quotes (symbol TEXT PRIMARY KEY, data TEXT NOT NULL, ts INTEGER);
CREATE TABLE IF NOT EXISTS fin_earnings (
    symbol TEXT, date TEXT, data TEXT NOT NULL, updated INTEGER, PRIMARY KEY(symbol, date));
CREATE TABLE IF NOT EXISTS ms_docs (
    id TEXT PRIMARY KEY, released TEXT, revision TEXT, data TEXT NOT NULL, summary INTEGER DEFAULT 0,
    channel_id INTEGER, message_id INTEGER, updated INTEGER);
CREATE TABLE IF NOT EXISTS ms_kbs (
    kb TEXT PRIMARY KEY, doc TEXT, data TEXT NOT NULL, rel_date TEXT, rel_type TEXT,
    posted INTEGER DEFAULT 0, channel_id INTEGER, message_id INTEGER, dirty INTEGER DEFAULT 0,
    first_seen INTEGER, updated INTEGER);
CREATE INDEX IF NOT EXISTS idx_ms_kbs_dirty ON ms_kbs(dirty);
CREATE INDEX IF NOT EXISTS idx_ms_kbs_doc ON ms_kbs(doc);
CREATE TABLE IF NOT EXISTS ms_kb_cves (cve TEXT, kb TEXT, PRIMARY KEY(cve, kb));
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY, description TEXT, applied INTEGER);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, type TEXT NOT NULL, ticker TEXT NOT NULL DEFAULT '', cik INTEGER,
    company TEXT, occurred_at TEXT NOT NULL, effective_session TEXT NOT NULL, session_timing TEXT NOT NULL,
    confidence REAL, source_refs TEXT, payload TEXT, dedup_key TEXT NOT NULL, created_at INTEGER,
    UNIQUE(type, ticker, dedup_key));
CREATE INDEX IF NOT EXISTS idx_events_ticker ON events(ticker, effective_session);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(type, effective_session);
CREATE TABLE IF NOT EXISTS prices (
    symbol TEXT NOT NULL, date TEXT NOT NULL, open REAL, high REAL, low REAL, close REAL, adj_close REAL,
    volume INTEGER, source TEXT, PRIMARY KEY(symbol, date));
CREATE TABLE IF NOT EXISTS price_splits (symbol TEXT NOT NULL, date TEXT NOT NULL, ratio REAL, PRIMARY KEY(symbol, date));
CREATE TABLE IF NOT EXISTS event_returns (event_id INTEGER PRIMARY KEY, data TEXT NOT NULL, computed INTEGER);
CREATE TABLE IF NOT EXISTS ms_releases (kb TEXT, build TEXT, date TEXT, type TEXT, PRIMARY KEY(kb, build));
"""

async def _m1_claims(db) -> None:
    async with db.execute("SELECT id, data FROM stories") as cur:
        rows = await cur.fetchall()
    for row in rows:
        data = json.loads(row["data"])
        claim = parse_claim(data.get("title"))
        if claim and data.get("claim") != claim:
            data["claim"] = claim
            await db.execute("UPDATE stories SET data=? WHERE id=?", (json.dumps(data), row["id"]))


MIGRATIONS = [
    (1, "ransomware.live claims: store group and victim on existing stories", _m1_claims),
]

SOURCE_FIELDS = {"last_ok", "last_err", "last_err_ts", "fails", "seeded", "items", "cursor"}


class Store:
    def __init__(self, path: str):
        self.path = path
        self.db: aiosqlite.Connection | None = None
        self._read_lock = asyncio.Lock()

    async def open(self) -> None:
        existed = self.path != ":memory:" and os.path.exists(self.path) and os.path.getsize(self.path) > 0
        self.db = await aiosqlite.connect(self.path)
        self.db.row_factory = aiosqlite.Row
        await self.db.executescript(SCHEMA)
        await self.db.commit()
        self.existed = existed
        await self.migrate(existed)

    async def schema_version(self) -> int:
        row = await self._one("SELECT MAX(version) AS v FROM schema_version")
        return int(row["v"] or 0)

    async def applied_migrations(self) -> set[int]:
        return {r["version"] for r in await self._all("SELECT version FROM schema_version")}

    async def migrate(self, existed: bool = True, migrations=None, context=None) -> list[int]:
        applied = await self.applied_migrations()
        pending = [m for m in (MIGRATIONS if migrations is None else migrations) if m[0] not in applied]
        if not pending:
            return []
        if existed and not getattr(self, "backup_path", None):
            self.backup_path = await self.backup()
            log.info("database backed up to %s before migration %s", self.backup_path,
                     ", ".join(str(m[0]) for m in pending))
        for version, description, step in pending:
            await step(self.db if context is None else context)
            await self.db.execute("INSERT INTO schema_version(version, description, applied) VALUES (?,?,?)",
                                  (version, description, int(time.time())))
            await self.db.commit()
            log.info("applied database migration %d: %s", version, description)
        return [m[0] for m in pending]

    async def backup(self) -> str:
        folder = os.path.join(os.path.dirname(os.path.abspath(self.path)), "backups")
        os.makedirs(folder, exist_ok=True)
        stem = os.path.splitext(os.path.basename(self.path))[0]
        target = os.path.join(folder, f"{stem}-{time.strftime('%Y%m%d-%H%M%S')}.db")
        suffix = 1
        while os.path.exists(target):
            target = os.path.join(folder, f"{stem}-{time.strftime('%Y%m%d-%H%M%S')}-{suffix}.db")
            suffix += 1
        await self.db.execute("VACUUM INTO ?", (target,))
        return target

    async def close(self) -> None:
        if self.db:
            await self.db.close()
            self.db = None

    async def _one(self, sql, args=()):
        async with self._read_lock, self.db.execute(sql, args) as cur:
            return await cur.fetchone()

    async def _all(self, sql, args=()):
        async with self._read_lock, self.db.execute(sql, args) as cur:
            return await cur.fetchall()

    async def _exec(self, sql, args=()):
        await self.db.execute(sql, args)
        await self.db.commit()

    async def seen_any(self, keys: list[str]) -> bool:
        if not keys:
            return False
        marks = ",".join("?" * len(keys))
        return await self._one(f"SELECT 1 FROM seen WHERE key IN ({marks}) LIMIT 1", keys) is not None

    async def mark_seen(self, keys: list[str], source: str) -> None:
        now = int(time.time())
        await self.db.executemany("INSERT OR IGNORE INTO seen(key, source, ts) VALUES (?,?,?)",
                                  [(k, source, now) for k in keys])
        await self.db.commit()

    async def http_cache_get(self, key: str):
        row = await self._one("SELECT etag, last_modified FROM http_cache WHERE key=?", (key,))
        return (row["etag"], row["last_modified"]) if row else (None, None)

    async def http_cache_set(self, key: str, etag: str | None, last_modified: str | None) -> None:
        await self._exec(
            "INSERT INTO http_cache(key, etag, last_modified) VALUES (?,?,?) "
            "ON CONFLICT(key) DO UPDATE SET etag=excluded.etag, last_modified=excluded.last_modified",
            (key, etag, last_modified))

    async def source_get(self, sid: str) -> dict:
        row = await self._one("SELECT * FROM sources WHERE id=?", (sid,))
        return dict(row) if row else {"id": sid, "fails": 0, "seeded": 0, "items": 0}

    async def source_update(self, sid: str, **fields) -> None:
        unknown = set(fields) - SOURCE_FIELDS
        if unknown:
            raise ValueError(f"unknown source fields: {unknown}")
        await self.db.execute("INSERT OR IGNORE INTO sources(id) VALUES (?)", (sid,))
        if fields:
            sets = ", ".join(f"{k}=?" for k in fields)
            await self.db.execute(f"UPDATE sources SET {sets} WHERE id=?", (*fields.values(), sid))
        await self.db.commit()

    async def all_sources(self) -> list[dict]:
        return [dict(r) for r in await self._all("SELECT * FROM sources")]

    async def vuln_resolve(self, ids: list[str]) -> str | None:
        ids = [i.upper() for i in ids if i]
        if not ids:
            return None
        marks = ",".join("?" * len(ids))
        row = await self._one(f"SELECT vid FROM aliases WHERE alias IN ({marks}) LIMIT 1", ids)
        return row["vid"] if row else None

    async def vuln_get(self, vid: str) -> dict | None:
        row = await self._one("SELECT * FROM vulns WHERE vid=?", (vid,))
        if not row:
            return None
        out = dict(row)
        out["data"] = json.loads(out["data"])
        return out

    async def vuln_put(self, vid: str, data: dict, aliases: list[str]) -> None:
        now = int(time.time())
        await self.db.execute(
            "INSERT INTO vulns(vid, data, first_seen, updated) VALUES (?,?,?,?) "
            "ON CONFLICT(vid) DO UPDATE SET data=excluded.data, updated=excluded.updated",
            (vid, json.dumps(data), now, now))
        await self.db.executemany("INSERT OR IGNORE INTO aliases(alias, vid) VALUES (?,?)",
                                  [(a.upper(), vid) for a in {*aliases, vid}])
        await self.db.commit()

    async def vuln_set_post(self, vid: str, posted: int, channel_id=None, message_id=None) -> None:
        await self._exec("UPDATE vulns SET posted=?, channel_id=?, message_id=?, dirty=0 WHERE vid=?",
                         (posted, channel_id, message_id, vid))

    async def vuln_mark_dirty(self, vid: str, dirty: int = 1) -> None:
        await self._exec("UPDATE vulns SET dirty=? WHERE vid=?", (dirty, vid))

    async def vulns_dirty(self, limit: int = 15) -> list[dict]:
        rows = await self._all(
            "SELECT * FROM vulns WHERE dirty=1 AND message_id IS NOT NULL ORDER BY updated LIMIT ?", (limit,))
        return [{**dict(r), "data": json.loads(r["data"])} for r in rows]

    async def vulns_recent(self, since: float) -> list[tuple[str, dict]]:
        rows = await self._all("SELECT vid, data FROM vulns WHERE first_seen>=? AND posted IN (0,1)",
                               (int(since),))
        return [(r["vid"], json.loads(r["data"])) for r in rows]

    async def story_insert(self, ts: float, tokens, cves, data: dict) -> int:
        cur = await self.db.execute(
            "INSERT INTO stories(ts, tokens, cves, data) VALUES (?,?,?,?)",
            (int(ts), json.dumps(sorted(tokens)), json.dumps(sorted(cves)), json.dumps(data)))
        await self.db.commit()
        return cur.lastrowid

    async def story_get(self, sid: int) -> dict | None:
        row = await self._one("SELECT * FROM stories WHERE id=?", (sid,))
        if not row:
            return None
        out = dict(row)
        out["data"] = json.loads(out["data"])
        return out

    async def story_update(self, sid: int, *, data=None, dirty=None, channel_id=None, message_id=None,
                           clear_message: bool = False) -> None:
        sets, args = [], []
        if data is not None:
            sets.append("data=?")
            args.append(json.dumps(data))
        if dirty is not None:
            sets.append("dirty=?")
            args.append(dirty)
        if message_id is not None or clear_message:
            sets += ["channel_id=?", "message_id=?"]
            args += [channel_id, message_id]
        if sets:
            await self._exec(f"UPDATE stories SET {', '.join(sets)} WHERE id=?", (*args, sid))

    async def stories_recent(self, since: float):
        rows = await self._all("SELECT id, ts, tokens, cves FROM stories WHERE ts>=? ORDER BY ts", (int(since),))
        return [(r["id"], r["ts"], json.loads(r["tokens"]), json.loads(r["cves"])) for r in rows]

    async def stories_dirty(self, limit: int = 15) -> list[dict]:
        rows = await self._all(
            "SELECT * FROM stories WHERE dirty=1 AND message_id IS NOT NULL ORDER BY ts LIMIT ?", (limit,))
        return [{**dict(r), "data": json.loads(r["data"])} for r in rows]

    async def fin_insert(self, ts: float, tickers: list[str], event: str, tokens, data: dict) -> int:
        cur = await self.db.execute(
            "INSERT INTO fin_items(ts, tickers, event, tokens, data) VALUES (?,?,?,?,?)",
            (int(ts), json.dumps(sorted(tickers)), event, json.dumps(sorted(tokens)), json.dumps(data)))
        await self.db.commit()
        return cur.lastrowid

    async def fin_get(self, fid: int) -> dict | None:
        row = await self._one("SELECT * FROM fin_items WHERE id=?", (fid,))
        if not row:
            return None
        return {**dict(row), "data": json.loads(row["data"])}

    async def fin_update(self, fid: int, *, data=None, tickers=None, dirty=None, channel_id=None,
                         message_id=None, clear_message: bool = False) -> None:
        sets, args = [], []
        if data is not None:
            sets.append("data=?")
            args.append(json.dumps(data))
        if tickers is not None:
            sets.append("tickers=?")
            args.append(json.dumps(sorted(tickers)))
        if dirty is not None:
            sets.append("dirty=?")
            args.append(dirty)
        if message_id is not None or clear_message:
            sets += ["channel_id=?", "message_id=?"]
            args += [channel_id, message_id]
        if sets:
            await self._exec(f"UPDATE fin_items SET {', '.join(sets)} WHERE id=?", (*args, fid))

    async def fin_recent(self, since: float):
        rows = await self._all("SELECT id, ts, tickers, event, tokens FROM fin_items WHERE ts>=? ORDER BY ts",
                               (int(since),))
        return [(r["id"], r["ts"], json.loads(r["tickers"]), r["event"], json.loads(r["tokens"])) for r in rows]

    async def fin_dirty(self, limit: int = 15) -> list[dict]:
        rows = await self._all(
            "SELECT * FROM fin_items WHERE dirty=1 AND message_id IS NOT NULL ORDER BY ts LIMIT ?", (limit,))
        return [{**dict(r), "data": json.loads(r["data"])} for r in rows]

    async def fin_for_ticker(self, ticker: str, limit: int = 5, since: float | None = None) -> list[dict]:
        rows = await self._all(
            "SELECT * FROM fin_items WHERE tickers LIKE ? AND ts>=? ORDER BY ts DESC LIMIT ?",
            (f'%"{ticker.upper()}"%', int(since or 0), limit))
        return [{**dict(r), "data": json.loads(r["data"])} for r in rows]

    async def quote_put(self, symbol: str, data: dict) -> None:
        await self._exec(
            "INSERT INTO fin_quotes(symbol, data, ts) VALUES (?,?,?) "
            "ON CONFLICT(symbol) DO UPDATE SET data=excluded.data, ts=excluded.ts",
            (symbol.upper(), json.dumps(data), int(time.time())))

    async def quote_get(self, symbol: str) -> tuple[dict, int] | None:
        row = await self._one("SELECT data, ts FROM fin_quotes WHERE symbol=?", (symbol.upper(),))
        return (json.loads(row["data"]), row["ts"]) if row else None

    async def earnings_replace(self, symbol: str, rows: list[dict], since: str) -> None:
        now = int(time.time())
        await self.db.execute("DELETE FROM fin_earnings WHERE symbol=? AND date>=?", (symbol.upper(), since))
        await self.db.executemany(
            "INSERT OR REPLACE INTO fin_earnings(symbol, date, data, updated) VALUES (?,?,?,?)",
            [(symbol.upper(), r["date"], json.dumps(r), now) for r in rows])
        await self.db.commit()

    async def earnings_between(self, start: str, end: str) -> list[dict]:
        rows = await self._all("SELECT data FROM fin_earnings WHERE date>=? AND date<=? ORDER BY date, symbol",
                               (start, end))
        return [json.loads(r["data"]) for r in rows]

    async def setting_get(self, key: str) -> str | None:
        row = await self._one("SELECT value FROM settings WHERE key=?", (key,))
        return row["value"] if row else None

    async def settings_get(self, prefix: str) -> dict[str, str]:
        rows = await self._all("SELECT key, value FROM settings WHERE key LIKE ? ORDER BY key", (prefix + "%",))
        return {r["key"][len(prefix):]: r["value"] for r in rows}

    async def setting_set(self, key: str, value: str) -> None:
        await self._exec("INSERT INTO settings(key, value) VALUES (?,?) "
                         "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))

    async def setting_delete(self, key: str) -> None:
        await self._exec("DELETE FROM settings WHERE key=?", (key,))

    async def digest_last(self) -> tuple[str, int] | None:
        row = await self._one("SELECT key, ts FROM seen WHERE key LIKE 'digest:%' ORDER BY ts DESC, key DESC LIMIT 1")
        return (row["key"].split(":", 1)[1], row["ts"]) if row else None

    async def stories_between(self, start: float, end: float) -> list[dict]:
        rows = await self._all("SELECT id, ts, data FROM stories WHERE ts>=? AND ts<? ORDER BY id",
                               (int(start), int(end)))
        return [{"id": r["id"], "ts": r["ts"], "data": json.loads(r["data"])} for r in rows]

    async def vulns_window(self, start: float, end: float) -> list[dict]:
        rows = await self._all(
            "SELECT vid, data, posted, first_seen FROM vulns WHERE (first_seen>=? AND first_seen<?) "
            "OR (updated>=? AND data LIKE '%\"kev\"%') ORDER BY vid", (int(start), int(end), int(start)))
        return [{"vid": r["vid"], "posted": r["posted"], "first_seen": r["first_seen"],
                 "data": json.loads(r["data"])} for r in rows]

    async def fin_between(self, start: float, end: float) -> list[dict]:
        rows = await self._all("SELECT id, ts, data FROM fin_items WHERE ts>=? AND ts<? ORDER BY id",
                               (int(start), int(end)))
        return [{"id": r["id"], "ts": r["ts"], "data": json.loads(r["data"])} for r in rows]

    async def quotes_all(self) -> list[tuple[str, dict, int]]:
        rows = await self._all("SELECT symbol, data, ts FROM fin_quotes ORDER BY symbol")
        return [(r["symbol"], json.loads(r["data"]), r["ts"]) for r in rows]

    async def ms_kbs_between(self, start: float, end: float) -> list[dict]:
        rows = await self._all(
            "SELECT * FROM ms_kbs WHERE first_seen>=? AND first_seen<? AND posted!=-1 ORDER BY kb",
            (int(start), int(end)))
        return [self._ms_kb(r) for r in rows]

    async def vuln_resolve_many(self, ids: list[str]) -> dict[str, str]:
        ids = [i.upper() for i in ids if i]
        out = {}
        for i in range(0, len(ids), 500):
            chunk = ids[i:i + 500]
            marks = ",".join("?" * len(chunk))
            for row in await self._all(f"SELECT alias, vid FROM aliases WHERE alias IN ({marks})", chunk):
                out[row["alias"]] = row["vid"]
        return out

    async def ms_doc_get(self, doc_id: str) -> dict | None:
        row = await self._one("SELECT * FROM ms_docs WHERE id=?", (doc_id,))
        return {**dict(row), "data": json.loads(row["data"])} if row else None

    async def ms_doc_put(self, doc_id: str, released: str | None, revision: str | None, data: dict,
                         summary: int | None = None) -> None:
        await self.db.execute(
            "INSERT INTO ms_docs(id, released, revision, data, updated) VALUES (?,?,?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET released=excluded.released, revision=excluded.revision, "
            "data=excluded.data, updated=excluded.updated",
            (doc_id, released, revision, json.dumps(data), int(time.time())))
        if summary is not None:
            await self.db.execute("UPDATE ms_docs SET summary=? WHERE id=? AND summary=0", (summary, doc_id))
        await self.db.commit()

    async def ms_doc_set_summary(self, doc_id: str, summary: int, channel_id=None, message_id=None) -> None:
        await self._exec("UPDATE ms_docs SET summary=?, channel_id=?, message_id=? WHERE id=?",
                         (summary, channel_id, message_id, doc_id))

    async def ms_docs_pending(self) -> list[dict]:
        rows = await self._all("SELECT * FROM ms_docs WHERE summary=0 ORDER BY id")
        return [{**dict(r), "data": json.loads(r["data"])} for r in rows]

    @staticmethod
    def _ms_kb(row) -> dict:
        out = dict(row)
        out["data"] = json.loads(out["data"])
        out["data"]["release"] = {"date": out["rel_date"], "type": out["rel_type"]}
        return out

    async def ms_kb_get(self, kb: str) -> dict | None:
        row = await self._one("SELECT * FROM ms_kbs WHERE kb=?", (kb,))
        return self._ms_kb(row) if row else None

    async def ms_kb_put(self, kb: str, data: dict, posted: int = 0) -> None:
        now = int(time.time())
        stored = json.dumps({k: v for k, v in data.items() if k != "release"})
        await self._exec(
            "INSERT INTO ms_kbs(kb, doc, data, posted, first_seen, updated) VALUES (?,?,?,?,?,?) "
            "ON CONFLICT(kb) DO UPDATE SET data=excluded.data, updated=excluded.updated",
            (kb, data.get("doc"), stored, posted, now, now))

    async def ms_kb_set_post(self, kb: str, posted: int, channel_id=None, message_id=None) -> None:
        await self._exec("UPDATE ms_kbs SET posted=?, channel_id=?, message_id=?, dirty=0 WHERE kb=?",
                         (posted, channel_id, message_id, kb))

    async def ms_kb_mark_dirty(self, kb: str, dirty: int = 1) -> None:
        await self._exec("UPDATE ms_kbs SET dirty=? WHERE kb=?", (dirty, kb))

    async def ms_kb_set_release(self, kb: str, released: str | None, kind: str | None) -> None:
        await self._exec(
            "UPDATE ms_kbs SET rel_date=?, rel_type=?, "
            "dirty=CASE WHEN posted=1 AND message_id IS NOT NULL THEN 1 ELSE dirty END WHERE kb=?",
            (released, kind, kb))

    async def ms_kbs_dirty(self, limit: int = 15) -> list[dict]:
        rows = await self._all(
            "SELECT * FROM ms_kbs WHERE dirty=1 AND message_id IS NOT NULL ORDER BY updated LIMIT ?", (limit,))
        return [self._ms_kb(r) for r in rows]

    async def ms_kbs_unposted(self, since: float) -> list[dict]:
        rows = await self._all("SELECT * FROM ms_kbs WHERE posted=0 AND first_seen>=? ORDER BY kb", (int(since),))
        return [self._ms_kb(r) for r in rows]

    async def ms_kbs_missing_release(self, since: float) -> list[str]:
        rows = await self._all("SELECT kb FROM ms_kbs WHERE rel_date IS NULL AND first_seen>=? ORDER BY kb",
                               (int(since),))
        return [r["kb"] for r in rows]

    async def ms_kbs_for_doc(self, doc_id: str) -> list[dict]:
        rows = await self._all("SELECT * FROM ms_kbs WHERE doc=? AND posted=1 ORDER BY kb", (doc_id,))
        return [self._ms_kb(r) for r in rows]

    async def ms_kb_cves_add(self, kb: str, cves) -> None:
        await self.db.executemany("INSERT OR IGNORE INTO ms_kb_cves(cve, kb) VALUES (?,?)",
                                  [(c.upper(), kb) for c in cves])
        await self.db.commit()

    async def ms_kbs_for_cves(self, ids: list[str]) -> list[str]:
        ids = [i.upper() for i in ids if i]
        if not ids:
            return []
        marks = ",".join("?" * len(ids))
        rows = await self._all(f"SELECT DISTINCT kb FROM ms_kb_cves WHERE cve IN ({marks}) ORDER BY kb", ids)
        return [r["kb"] for r in rows]

    async def ms_releases_put(self, rows: list[tuple[str, str, str, str]]) -> None:
        await self.db.executemany(
            "INSERT INTO ms_releases(kb, build, date, type) VALUES (?,?,?,?) "
            "ON CONFLICT(kb, build) DO UPDATE SET date=excluded.date, type=excluded.type", rows)
        await self.db.commit()

    async def ms_release_get(self, kb: str) -> tuple[str, str] | None:
        row = await self._one("SELECT date, type FROM ms_releases WHERE kb=? ORDER BY date LIMIT 1", (kb,))
        return (row["date"], row["type"]) if row else None

    @staticmethod
    def _event(row) -> dict:
        out = dict(row)
        out["source_refs"] = json.loads(out["source_refs"] or "{}")
        out["payload"] = json.loads(out["payload"] or "{}")
        return out

    async def event_put(self, ev: dict) -> tuple[int, bool]:
        cur = await self.db.execute(
            "INSERT OR IGNORE INTO events(type, ticker, cik, company, occurred_at, effective_session, session_timing, "
            "confidence, source_refs, payload, dedup_key, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (ev["type"], ev["ticker"], ev["cik"], ev["company"], ev["occurred_at"], ev["effective_session"],
             ev["session_timing"], ev["confidence"], json.dumps(ev["source_refs"], sort_keys=True),
             json.dumps(ev["payload"], sort_keys=True), ev["dedup_key"], ev["created_at"]))
        await self.db.commit()
        if cur.rowcount:
            return cur.lastrowid, True
        row = await self._one("SELECT id FROM events WHERE type=? AND ticker=? AND dedup_key=?",
                              (ev["type"], ev["ticker"], ev["dedup_key"]))
        return row["id"], False

    async def event_get(self, event_id: int) -> dict | None:
        row = await self._one("SELECT * FROM events WHERE id=?", (event_id,))
        return self._event(row) if row else None

    async def event_merge_refs(self, event_id: int, refs: dict) -> None:
        current = await self.event_get(event_id)
        if current is None:
            return
        merged = {**current["source_refs"], **refs}
        await self._exec("UPDATE events SET source_refs=? WHERE id=?", (json.dumps(merged, sort_keys=True), event_id))

    async def events_query(self, *, type_: str | None = None, ticker: str | None = None, cik: int | None = None,
                           since: str | None = None, until: str | None = None) -> list[dict]:
        sql, args = "SELECT * FROM events WHERE 1=1", []
        for column, value in (("type", type_), ("ticker", ticker.upper() if ticker else None), ("cik", cik)):
            if value is not None:
                sql += f" AND {column}=?"
                args.append(value)
        if since:
            sql += " AND effective_session>=?"
            args.append(since)
        if until:
            sql += " AND effective_session<=?"
            args.append(until)
        rows = await self._all(sql + " ORDER BY effective_session, occurred_at, id", args)
        return [self._event(r) for r in rows]

    async def event_counts(self) -> dict[str, int]:
        rows = await self._all("SELECT type, COUNT(*) AS n FROM events GROUP BY type ORDER BY type")
        return {r["type"]: r["n"] for r in rows}

    async def event_tickers(self) -> list[str]:
        rows = await self._all("SELECT DISTINCT ticker FROM events WHERE ticker!='' ORDER BY ticker")
        return [r["ticker"] for r in rows]

    async def prices_put(self, symbol: str, rows: list[dict], source: str) -> None:
        await self.db.executemany(
            "INSERT INTO prices(symbol, date, open, high, low, close, adj_close, volume, source) VALUES (?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(symbol, date) DO UPDATE SET open=excluded.open, high=excluded.high, low=excluded.low, "
            "close=excluded.close, adj_close=excluded.adj_close, volume=excluded.volume, source=excluded.source",
            [(symbol.upper(), r["date"], r.get("open"), r.get("high"), r.get("low"), r.get("close"), r.get("adj_close"),
              r.get("volume"), source) for r in rows])
        await self.db.commit()

    async def prices_for(self, symbol: str) -> list[dict]:
        rows = await self._all("SELECT date, open, high, low, close, adj_close, volume FROM prices WHERE symbol=? "
                               "ORDER BY date", (symbol.upper(),))
        return [dict(r) for r in rows]

    async def price_bounds(self) -> dict[str, tuple[str, str, int]]:
        rows = await self._all("SELECT symbol, MIN(date) AS a, MAX(date) AS b, COUNT(*) AS n FROM prices GROUP BY symbol")
        return {r["symbol"]: (r["a"], r["b"], r["n"]) for r in rows}

    async def splits_put(self, symbol: str, splits: list[tuple[str, float]]) -> None:
        await self.db.executemany("INSERT OR REPLACE INTO price_splits(symbol, date, ratio) VALUES (?,?,?)",
                                  [(symbol.upper(), d, r) for d, r in splits])
        await self.db.commit()

    async def splits_for(self, symbol: str) -> dict[str, float]:
        rows = await self._all("SELECT date, ratio FROM price_splits WHERE symbol=?", (symbol.upper(),))
        return {r["date"]: r["ratio"] for r in rows}

    async def event_return_get(self, event_id: int) -> dict | None:
        row = await self._one("SELECT data FROM event_returns WHERE event_id=?", (event_id,))
        return json.loads(row["data"]) if row else None

    async def event_return_put(self, event_id: int, data: dict) -> None:
        await self._exec("INSERT OR REPLACE INTO event_returns(event_id, data, computed) VALUES (?,?,?)",
                         (event_id, json.dumps(data, sort_keys=True), int(time.time())))

    async def prune(self) -> None:
        now = int(time.time())
        old_kbs = now - 400 * 86400
        await self.db.execute("DELETE FROM ms_kb_cves WHERE kb IN (SELECT kb FROM ms_kbs WHERE first_seen<?)",
                              (old_kbs,))
        await self.db.execute("DELETE FROM ms_kbs WHERE first_seen<?", (old_kbs,))
        await self.db.execute("DELETE FROM seen WHERE ts<? AND (key LIKE 'mskb:%' OR key LIKE 'digest:%')",
                              (now - 30 * 86400,))
        await self.db.execute("DELETE FROM fin_items WHERE ts<?", (now - 30 * 86400,))
        await self.db.execute("DELETE FROM fin_earnings WHERE updated<?", (now - 30 * 86400,))
        await self.db.execute("DELETE FROM seen WHERE ts<? AND key LIKE 'fin:%'", (now - 30 * 86400,))
        await self.db.execute("DELETE FROM seen WHERE ts<? AND (key LIKE 'u:%' OR key LIKE 'g:%')",
                              (now - 120 * 86400,))
        await self.db.execute("DELETE FROM stories WHERE ts<?", (now - 30 * 86400,))
        stale = now - 60 * 86400
        await self.db.execute(
            "DELETE FROM aliases WHERE vid IN (SELECT vid FROM vulns WHERE posted=0 AND updated<?)", (stale,))
        await self.db.execute("DELETE FROM vulns WHERE posted=0 AND updated<?", (stale,))
        await self.db.commit()
