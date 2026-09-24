from __future__ import annotations

import asyncio
import json
import time

import aiosqlite

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
"""

SOURCE_FIELDS = {"last_ok", "last_err", "last_err_ts", "fails", "seeded", "items", "cursor"}


class Store:
    def __init__(self, path: str):
        self.path = path
        self.db: aiosqlite.Connection | None = None
        self._read_lock = asyncio.Lock()

    async def open(self) -> None:
        self.db = await aiosqlite.connect(self.path)
        self.db.row_factory = aiosqlite.Row
        await self.db.executescript(SCHEMA)
        await self.db.commit()

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

    async def prune(self) -> None:
        now = int(time.time())
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
