from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timezone

from .. import msrc, render
from ..http import FetchError
from .base import Source

JSON_ACCEPT = {"Accept": "application/json"}
HTML_ACCEPT = {"Accept": "text/html"}
DOCUMENT_TIMEOUT = 180
RECENT_DAYS = 60
RETRY_POST_DAYS = 7

log = logging.getLogger(__name__)


class MSRCCvrfSource(Source):
    fast_interval = float("inf")

    def __init__(self, app, cfg: dict):
        super().__init__(app, cfg)
        self.interval = float(cfg.get("interval") or 10800)
        self.fast_interval = float(cfg.get("patch_tuesday_interval") or 1800)
        self.months = max(1, int(cfg.get("months") or 2))
        self.products = list(cfg.get("products") or msrc.DEFAULT_PRODUCTS)
        self.channel = cfg.get("channel", "microsoft")
        self.url = cfg.get("url") or msrc.UPDATES_URL

    @property
    def interval(self) -> float:
        if msrc.in_patch_window(datetime.now(timezone.utc)):
            return min(self._interval, self.fast_interval)
        return self._interval

    @interval.setter
    def interval(self, value: float) -> None:
        self._interval = float(value)

    async def poll(self, seed: bool) -> int:
        app, store = self.app, self.app.store
        fetched = await app.http.get(self.url, headers=JSON_ACCEPT, conditional=True)
        entries = []
        if fetched is not None:
            entries = sorted((e for e in json.loads(fetched.body).get("value") or [] if e.get("ID")),
                             key=lambda e: e.get("InitialReleaseDate") or "")
        tracked = entries[-self.months:]
        newest = tracked[-1]["ID"] if tracked else None

        changed = []
        for entry in tracked:
            row = await store.ms_doc_get(entry["ID"])
            if row is None or row["released"] != entry.get("CurrentReleaseDate"):
                changed.append((entry, row))

        recent = time.time() - RECENT_DAYS * 86400
        if changed or await store.ms_kbs_missing_release(recent):
            await self.refresh_releases()

        count = 0
        for entry, row in changed:
            quiet = seed or (row is None and entry["ID"] != newest)
            url = entry.get("CvrfUrl") or f"{self.url.rsplit('/', 1)[0]}/cvrf/{entry['ID']}"
            body = (await app.http.get(url, headers=JSON_ACCEPT, conditional=False, timeout=DOCUMENT_TIMEOUT)).body
            doc = await asyncio.to_thread(msrc.parse_document, body, self.products)
            count += await self.apply(doc, entry["ID"], quiet)
            summary = {k: doc[k] for k in ("title", "total", "exploited", "disclosed")}
            await store.ms_doc_put(entry["ID"], entry.get("CurrentReleaseDate"), doc["revision"], summary,
                                   summary=-1 if quiet and doc["kbs"] else None)

        await self.fill_releases(recent)
        if not seed:
            await self.post_pending()
            await self.post_summaries()
        await app.http.commit(fetched)
        return count

    async def apply(self, doc: dict, doc_id: str, quiet: bool) -> int:
        store, poster = self.app.store, self.app.poster
        count = 0
        for kb in sorted(doc["kbs"]):
            new = doc["kbs"][kb]
            for cve in new["cves"].values():
                cve["doc"] = doc_id
            row = await store.ms_kb_get(kb)
            if row is None:
                await store.ms_kb_put(kb, {**new, "doc": doc_id}, posted=-1 if quiet else 0)
                await self.crosslink(kb, sorted(new["cves"]), quiet)
                count += 1
                continue

            old = row["data"]
            cves = {c: v for c, v in old["cves"].items() if v.get("doc") != doc_id}
            cves.update(new["cves"])
            data = msrc.finalize({**old, "cves": cves, "subtype": new["subtype"] or old.get("subtype"),
                                  "supersedes": new["supersedes"] or old.get("supersedes") or []})
            if data == old:
                continue
            await store.ms_kb_put(kb, data)
            await self.crosslink(kb, sorted(set(cves) - set(old["cves"])), quiet)
            if row["posted"] != 1 or not row["message_id"]:
                continue
            await store.ms_kb_mark_dirty(kb)
            parts = msrc.diff_kb(old, data)
            if parts and not quiet:
                jump = poster.jump_url(row["channel_id"], row["message_id"])
                await poster.send(self.channel, content=msrc.revision_line(kb, parts, jump))
                count += 1
        return count

    async def crosslink(self, kb: str, cves: list[str], quiet: bool) -> None:
        if not cves:
            return
        await self.app.store.ms_kb_cves_add(kb, cves)
        known = await self.app.store.vuln_resolve_many(cves)
        ref = {f"Fixed in KB{kb}": msrc.kb_url(kb)}
        for vid in sorted(set(known.values())):
            await self.app.vulns.ingest({"id": vid, "refs": dict(ref)}, seed=quiet)

    async def refresh_releases(self) -> None:
        for url in self.cfg.get("release_pages") or msrc.RELEASE_PAGES:
            try:
                fetched = await self.app.http.get(url, headers=HTML_ACCEPT, conditional=True)
            except FetchError as exc:
                log.warning("release information page %s failed: %s", url, exc)
                continue
            if fetched is None:
                continue
            rows = await asyncio.to_thread(msrc.parse_release_tables, fetched.body)
            if not rows:
                log.warning("no release rows found on %s (page layout changed?)", url)
                continue
            await self.app.store.ms_releases_put(rows)
            await self.app.http.commit(fetched)

    async def fill_releases(self, since: float) -> None:
        store = self.app.store
        for kb in await store.ms_kbs_missing_release(since):
            release = await store.ms_release_get(kb) or await self.support_page(kb)
            if release:
                await store.ms_kb_set_release(kb, *release)

    async def support_page(self, kb: str) -> tuple[str, str | None] | None:
        key = f"mskb:{kb}:{datetime.now(timezone.utc):%Y-%m-%d}"
        if await self.app.store.seen_any([key]):
            return None
        await self.app.store.mark_seen([key], self.id)
        try:
            fetched = await self.app.http.get(msrc.kb_url(kb), headers=HTML_ACCEPT, conditional=False)
        except FetchError as exc:
            log.info("support page for KB%s unavailable: %s", kb, exc)
            return None
        return await asyncio.to_thread(msrc.parse_support_title, fetched.body, kb)

    async def post_pending(self) -> None:
        store = self.app.store
        for row in await store.ms_kbs_unposted(time.time() - RETRY_POST_DAYS * 86400):
            data = row["data"]
            msg = await self.app.poster.send(self.channel, embed=render.kb_embed(data), ping_microsoft=True,
                                             file=(msrc.tsv_name(row["kb"]), msrc.kb_tsv(data)))
            if msg:
                await store.ms_kb_set_post(row["kb"], 1, msg.channel.id, msg.id)

    async def post_summaries(self) -> None:
        store, poster = self.app.store, self.app.poster
        now = datetime.now(timezone.utc)
        for doc in await store.ms_docs_pending():
            due = msrc.patch_time(doc["id"])
            if due and now < due:
                continue
            rows = await store.ms_kbs_for_doc(doc["id"])
            if not rows:
                continue
            cards = [(r["data"], poster.jump_url(r["channel_id"], r["message_id"])) for r in rows]
            msg = await poster.send(self.channel, embed=render.patch_summary_embed(doc["id"], doc["data"], cards))
            if msg:
                await store.ms_doc_set_summary(doc["id"], 1, msg.channel.id, msg.id)
