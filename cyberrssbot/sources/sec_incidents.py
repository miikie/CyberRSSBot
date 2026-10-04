from __future__ import annotations

import logging
from datetime import datetime, timezone

from .. import incidents
from ..http import FetchError
from ..market import NY
from ..util import parse_time
from .base import Source

log = logging.getLogger(__name__)

MAX_PAGES = 5
PAGE = 100


def sec_headers(app, accept: str = "text/html,application/xhtml+xml") -> dict:
    ua = app.cfg["secrets"].get("sec_user_agent")
    if not ua:
        raise FetchError("SEC_USER_AGENT or MAIN_EMAIL is not set")
    return {"User-Agent": ua, "Accept": accept}


async def fetch_text(app, url: str) -> str:
    fetched = await app.http.get(url, headers=sec_headers(app), conditional=False)
    return incidents.filing_text(fetched.body)


async def record_filing(app, *, form: str, cik: int, company: str, accession: str, items: list[str], accepted,
                        doc_url: str, text: str, index_url: str | None = None, post: bool = False,
                        date_only: bool = False) -> tuple[int | None, bool]:
    base = form.upper().replace("/A", "")
    if base != "8-K":
        return None, False
    amended = form.upper().endswith("/A")
    listed = app.companies.by_cik_company(cik)
    ticker = listed.ticker if listed else ""
    refs = {"filing": index_url or doc_url, "document": doc_url, "accession": accession}
    keywords = app.incidents.keywords
    if "1.05" in items:
        section = incidents.item_section(text, "1.05") or text
        features = incidents.severity(section)
        prior = [e for e in await app.store.events_query(cik=cik)
                 if e["type"] in ("sec.8k.1_05", "sec.8k.1_05_amendment")
                 and e["source_refs"].get("accession") != accession]
        original = next((e for e in reversed(prior) if e["type"] == "sec.8k.1_05"), None)
        amendments = sum(1 for e in prior if e["type"] == "sec.8k.1_05_amendment") + (1 if amended else 0)
        type_ = "sec.8k.1_05_amendment" if amended else "sec.8k.1_05"
        payload = {"form": form, "items": items, "features": features, "amendments": amendments if amended else 0,
                   "exchange": listed.exchange if listed else None}
    elif "8.01" in items:
        section = incidents.item_section(text, "8.01")
        hits = incidents.cyber_keywords(section, keywords)
        if not hits:
            return None, False
        type_, original = "sec.8k.8_01_cyber", None
        payload = {"form": form, "items": items, "keywords": hits, "features": incidents.severity(section),
                   "exchange": listed.exchange if listed else None}
    else:
        return None, False
    event_id, created = await app.events.record(
        type_, ticker=ticker, cik=cik, company=company or (listed.name if listed else None), occurred_at=accepted,
        dedup=accession, confidence=1.0 if listed else 0.0, refs=refs, payload=payload, date_only=date_only)
    if created and post:
        await app.incidents.post_filing(event_id, original=original)
    return event_id, created


class SECIncidentsSource(Source):
    def __init__(self, app, cfg):
        super().__init__(app, cfg)
        self.idle_interval = float(cfg.get("idle_interval", 3600))

    def next_interval(self) -> float:
        ny = datetime.now(timezone.utc).astimezone(NY)
        return self.interval if ny.weekday() < 5 and 6 <= ny.hour < 22 else self.idle_interval

    async def entries(self) -> list[dict]:
        app, store = self.app, self.app.store
        out = []
        for page in range(MAX_PAGES):
            params = {"action": "getcurrent", "type": "8-K", "company": "", "dateb": "", "owner": "include",
                      "start": str(page * PAGE), "count": str(PAGE), "output": "atom"}
            fetched = await app.http.get(incidents.ATOM_URL, params=params,
                                         headers=sec_headers(app, "application/atom+xml"), conditional=False)
            batch = incidents.parse_atom(fetched.body)
            out += batch
            if len(batch) < PAGE or await store.seen_any(["s8k:" + e["accession"] for e in batch]):
                break
        return out

    async def poll(self, seed: bool) -> int:
        app, store = self.app, self.app.store
        count = 0
        entries = await self.entries()
        for entry in sorted(entries, key=lambda e: e["accepted"] or ""):
            key = "s8k:" + entry["accession"]
            if await store.seen_any([key]):
                continue
            wanted = "1.05" in entry["items"] or "8.01" in entry["items"]
            if not wanted or not entry["form"].upper().startswith("8-K"):
                await store.mark_seen([key], self.id)
                continue
            try:
                index = await app.http.get(entry["index_url"], headers=sec_headers(app), conditional=False)
                doc = incidents.primary_document(index.body, entry["form"], entry["index_url"])
                if doc is None:
                    raise FetchError(f"no primary document in {entry['index_url']}")
                text = await fetch_text(app, doc)
            except FetchError as exc:
                log.warning("sec_incidents: %s %s skipped: %s", entry["company"], entry["accession"], exc)
                continue
            _, created = await record_filing(
                app, form=entry["form"], cik=entry["cik"], company=entry["company"], accession=entry["accession"],
                items=entry["items"], accepted=parse_time(entry["accepted"]) or datetime.now(timezone.utc),
                doc_url=doc, text=text, index_url=entry["index_url"], post=not seed)
            await store.mark_seen([key], self.id)
            count += int(created)
        return count
