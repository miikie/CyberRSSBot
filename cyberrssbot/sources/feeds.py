from __future__ import annotations

import html
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import urljoin

import feedparser
from bs4 import BeautifulSoup

from ..dedup import CVE_RE, canonical_url, key_hash
from ..http import FetchError
from .base import Source

_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")
_EPOCH = datetime.min.replace(tzinfo=timezone.utc)


def clean_text(value: str | None) -> str:
    if not value:
        return ""
    return _WS_RE.sub(" ", html.unescape(_TAG_RE.sub(" ", value))).strip()


def _entry_time(entry) -> datetime | None:
    t = entry.get("published_parsed") or entry.get("updated_parsed")
    if not t:
        return None
    try:
        return datetime(*t[:6], tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


class FeedLikeSource(Source):
    def __init__(self, app, cfg):
        super().__init__(app, cfg)
        self.url = cfg["url"]
        self.kind = cfg.get("kind", "news")
        self.include = [k.lower() for k in cfg.get("include_keywords") or []]
        self.exclude = [k.lower() for k in cfg.get("exclude_keywords") or []]
        self.max_age = timedelta(days=float(cfg.get("max_age_days", app.cfg["poll"]["max_age_days"])))
        self.max_items = int(cfg.get("max_items", 60))
        self.cluster = bool(cfg.get("cluster", True))
        self.tickers = cfg.get("tickers")
        if self.tickers is not None:
            self.kind = "finance"
        self.lookback = timedelta(hours=float(cfg.get("first_run_lookback_hours",
                                                      app.cfg["poll"].get("first_run_lookback_hours", 0))))

    def _wanted(self, e: dict) -> bool:
        hay = f"{e['title']} {e['summary']}".lower()
        if self.include and not any(k in hay for k in self.include):
            return False
        if any(k in hay for k in self.exclude):
            return False
        if e["published"] and datetime.now(timezone.utc) - e["published"] > self.max_age:
            return False
        return True

    def _backfill(self, e: dict, now: datetime) -> bool:
        return bool(self.lookback and e["published"] and timedelta(0) <= now - e["published"] <= self.lookback)

    async def process(self, entries: list[dict], seed: bool) -> int:
        store = self.app.store
        count = 0
        now = datetime.now(timezone.utc)
        entries.sort(key=lambda e: e["published"] or _EPOCH)
        for e in entries:
            keys = ["u:" + key_hash(canonical_url(e["url"]))]
            if e.get("guid"):
                keys.append("g:" + key_hash(f"{self.id}|{e['guid']}"))
            if await store.seen_any(keys):
                continue
            if self._wanted(e):
                quiet = seed and not self._backfill(e, now)
                if self.kind == "vuln":
                    await self._ingest_vuln(e, quiet)
                elif self.kind == "finance":
                    await self.app.finance.ingest_feed_item(self, e, quiet)
                else:
                    item = {
                        "title": e["title"] or e["url"], "url": e["url"], "summary": e["summary"],
                        "source": self.name,
                        "published": e["published"].isoformat() if e["published"] else None,
                    }
                    await self.app.stories.ingest(item, seed=quiet, channel_key=self.channel, cluster=self.cluster)
                count += 1
            await store.mark_seen(keys, self.id)
        return count

    async def _ingest_vuln(self, e: dict, seed: bool) -> None:
        cves = {c.upper() for c in CVE_RE.findall(e["title"])} or \
               {c.upper() for c in CVE_RE.findall(e["summary"])[:5]}
        for cve in sorted(cves):
            title = CVE_RE.sub("", e["title"]).strip(" :-–—|") or None
            partial = {"id": cve, "title": title, "refs": {self.name: e["url"]}}
            if self.cfg.get("vendor"):
                partial["vendor"] = self.cfg["vendor"]
            await self.app.vulns.ingest(partial, seed=seed)


class RSSSource(FeedLikeSource):
    async def poll(self, seed: bool) -> int:
        fetched = await self.app.http.get(self.url, conditional=True)
        if fetched is None:
            return 0
        feed = feedparser.parse(fetched.body)
        if not feed.entries:
            if feed.bozo:
                raise FetchError(f"unparseable feed: {feed.get('bozo_exception')}")
            await self.app.http.commit(fetched)
            return 0
        entries = []
        for entry in feed.entries[: self.max_items]:
            url = entry.get("feedburner_origlink") or entry.get("link")
            if not url:
                continue
            entries.append({
                "title": clean_text(entry.get("title")),
                "url": url.strip(),
                "guid": entry.get("id") or entry.get("guid"),
                "summary": clean_text(entry.get("summary")),
                "published": _entry_time(entry),
            })
        count = await self.process(entries, seed)
        await self.app.http.commit(fetched)
        return count


class ScrapeSource(FeedLikeSource):
    async def poll(self, seed: bool) -> int:
        fetched = await self.app.http.get(self.url, conditional=True,
                                          headers={"Accept": "text/html,application/xhtml+xml"})
        if fetched is None:
            return 0
        soup = BeautifulSoup(fetched.body, "html.parser")
        elements = soup.select(self.cfg["item_selector"])
        if not elements:
            raise FetchError(f"selector {self.cfg['item_selector']!r} matched nothing (page layout changed?)")
        entries, seen_urls = [], set()
        for el in elements[: self.max_items]:
            link = el if el.name == "a" else el.find("a", href=True)
            if not link or not link.get("href"):
                continue
            url = urljoin(self.url, link["href"])
            if url in seen_urls:
                continue
            seen_urls.add(url)
            title_el = el.select_one(self.cfg["title_selector"]) if self.cfg.get("title_selector") else link
            entries.append({
                "title": clean_text(title_el.get_text(" ") if title_el else ""),
                "url": url, "guid": None, "summary": "", "published": None,
            })
        count = await self.process(entries, seed)
        await self.app.http.commit(fetched)
        return count
