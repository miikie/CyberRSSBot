from __future__ import annotations

import logging
import re
import time
from datetime import datetime, timedelta, timezone

from . import render
from .dedup import fingerprint, similarity

log = logging.getLogger(__name__)

ITEM_LABELS = {
    "1.01": "Material agreement",
    "1.02": "Agreement terminated",
    "2.01": "Acquisition or disposition completed",
    "2.02": "Earnings results",
    "2.05": "Restructuring",
    "3.01": "Listing notice",
    "5.02": "Executive or director change",
    "5.07": "Shareholder vote results",
    "7.01": "Other announcement",
    "8.01": "Other announcement",
}
ITEM_EVENTS = [
    ("2.02", "earnings"),
    ("2.01", "mna"),
    ("1.01", "mna"),
    ("1.02", "mna"),
    ("5.02", "leadership"),
    ("2.05", "restructuring"),
    ("3.01", "listing"),
    ("5.07", "vote"),
    ("7.01", "other"),
    ("8.01", "other"),
]
FORM_INFO = {
    "8-K": ("Current report", None),
    "6-K": ("Current report (foreign issuer)", "other"),
    "10-Q": ("Quarterly report", "periodic"),
    "10-K": ("Annual report", "periodic"),
    "20-F": ("Annual report (foreign issuer)", "periodic"),
    "S-1": ("Registration statement", "offering"),
    "DEFM14A": ("Merger proxy", "mna"),
    "SC TO-T": ("Third-party tender offer", "mna"),
    "SC TO-I": ("Issuer tender offer", "buyback"),
    "SCHEDULE 13D": ("Activist stake", "stake"),
    "SCHEDULE 13G": ("Passive stake", "stake"),
    "4": ("Insider transaction", "insider"),
}
FORM_ALIASES = {"SC 13D": "SCHEDULE 13D", "SC 13G": "SCHEDULE 13G"}
DEFAULT_FORMS = {"8-K", "6-K", "10-Q", "10-K", "20-F", "S-1", "DEFM14A", "SC TO-T", "SC TO-I", "SCHEDULE 13D"}
AMENDMENTS_KEPT = {"8-K", "SCHEDULE 13D", "SCHEDULE 13G"}

EVENT_PATTERNS = [
    ("earnings_date", re.compile(r"\bto (announce|report|release|host)\b.*\b(results|earnings)\b", re.I)),
    ("earnings", re.compile(
        r"\b(reports?|announces?|posts?|delivers?)\b.*\b(results|earnings)\b"
        r"|\b(quarter(ly)?|fiscal|q[1-4]|full[- ]year)\b.*\bresults\b"
        r"|\bearnings\b", re.I)),
    ("mna", re.compile(
        r"\b(acquir\w*|acquisition|merger|merges?|to be acquired|definitive agreement|takeover"
        r"|take[- ]private|buyout|tender offer)\b", re.I)),
    ("guidance", re.compile(r"\b(guidance|outlook|forecast)\b", re.I)),
    ("leadership", re.compile(
        r"\b(appoint\w*|names?|named|hires?|steps? down|resign\w*|retire\w*|successor|depart\w*)\b"
        r".*\b(ceo|cfo|coo|cto|ciso|chief|president|chair\w*|board|director)\b"
        r"|\b(ceo|cfo|coo|chief \w+ officer)\b.*\b(appoint\w*|named|steps? down|resign\w*|depart\w*|retire\w*)\b",
        re.I)),
    ("buyback", re.compile(r"\b(share repurchase|buyback|repurchase program)\b", re.I)),
    ("offering", re.compile(r"\b(initial public offering|ipo|convertible (senior )?notes|notes offering)\b", re.I)),
]


def normalize_form(form: str) -> tuple[str, bool]:
    form = (form or "").strip().upper()
    amended = form.endswith("/A")
    base = form[:-2] if amended else form
    return FORM_ALIASES.get(base, base), amended


def describe_filing(form: str, items: str | None) -> tuple[str, str] | None:
    base, _ = normalize_form(form)
    if base == "8-K":
        codes = [c.strip() for c in (items or "").split(",") if c.strip()]
        meaningful = [c for c in codes if c != "9.01"]
        if codes and not meaningful:
            return None
        labels = list(dict.fromkeys(ITEM_LABELS.get(c, f"Item {c}") for c in meaningful))
        event = next((ev for code, ev in ITEM_EVENTS if code in meaningful), "other")
        return event, ", ".join(labels) or "Current report"
    label, event = FORM_INFO.get(base, (base, "other"))
    return event or "other", label


def classify(text: str) -> str:
    for event, pattern in EVENT_PATTERNS:
        if pattern.search(text or ""):
            return event
    return "other"


class Watchlist:
    def __init__(self, fcfg: dict):
        self.companies: dict[str, dict] = {}
        for ticker, info in (fcfg.get("companies") or {}).items():
            info = dict(info or {})
            info.setdefault("name", ticker)
            self.companies[str(ticker).upper()] = info
        self.benchmarks: dict[str, str] = {str(k).upper(): str(v) for k, v in (fcfg.get("benchmarks") or {}).items()}
        self._by_cik = {int(i["cik"]): t for t, i in self.companies.items() if i.get("cik")}
        self._patterns = []
        for ticker, info in self.companies.items():
            names = [info["name"], *(info.get("aliases") or [])]
            words = "|".join(re.escape(n) for n in sorted(set(names), key=len, reverse=True))
            sym = re.escape(ticker)
            self._patterns.append((ticker, re.compile(
                rf"(?<![\w-])(?:{words})(?![\w-])"
                rf"|\((?:nasdaq|nyse|nasdaqgs|nyse american)\s*:\s*{sym}\)"
                rf"|\${sym}\b", re.I)))

    def detect(self, text: str) -> set[str]:
        return {t for t, p in self._patterns if p.search(text or "")}

    def ticker_for_cik(self, cik) -> str | None:
        return self._by_cik.get(int(cik))

    def name(self, symbol: str) -> str:
        symbol = symbol.upper()
        if symbol in self.companies:
            return self.companies[symbol]["name"]
        return self.benchmarks.get(symbol, symbol)

    def symbols(self) -> dict[str, str]:
        return {**{t: i["name"] for t, i in self.companies.items()}, **self.benchmarks}


class FinanceEngine:
    def __init__(self, app):
        self.app = app
        f = app.cfg["finance"]
        self.cfg = f
        self.watch = Watchlist(f)
        self.window = float(f.get("cluster_window_hours", 48)) * 3600
        self.threshold = float(app.cfg["dedup"]["title_threshold"])
        self._recent: list[dict] = []

    async def load(self) -> None:
        for fid, ts, tickers, event, tokens in await self.app.store.fin_recent(time.time() - self.window):
            self._recent.append({"id": fid, "ts": ts, "tickers": set(tickers), "event": event,
                                 "tokens": frozenset(tokens)})

    def _match(self, tickers: set[str], event: str, tokens: frozenset, now: float) -> dict | None:
        self._recent = [r for r in self._recent if now - r["ts"] <= self.window]
        best, best_score = None, 0.0
        for r in self._recent:
            if not tickers & r["tickers"]:
                continue
            if event != "other" and event == r["event"]:
                return r
            score = similarity(tokens, r["tokens"])
            if min(len(tokens), len(r["tokens"])) >= 3 and score >= self.threshold and score > best_score:
                best, best_score = r, score
        return best

    async def ingest(self, item: dict, *, seed: bool) -> None:
        store = self.app.store
        tickers = {t.upper() for t in item["tickers"]}
        if not tickers:
            return
        tokens, _ = fingerprint(item["title"])
        now = time.time()
        match = self._match(tickers, item["event"], tokens, now)
        if match:
            row = await store.fin_get(match["id"])
            if row:
                await self._merge(row, match, item, tickers)
                return

        data = {
            "tickers": sorted(tickers), "event": item["event"], "kind": item["kind"],
            "title": item["title"], "url": item["url"], "source": item["source"],
            "summary": item.get("summary") or "", "published": item.get("published"),
            "filings": [], "also": [],
        }
        if item["kind"] == "filing":
            data["filings"].append({"label": item["filing_label"], "url": item["url"]})
        if item["kind"] != "filing":
            data["tone"] = self.app.fsignals.lexicon.score(f"{data['title']}. {data['summary']}")
        fid = await store.fin_insert(now, data["tickers"], item["event"], tokens, data)
        if item["kind"] != "filing":
            await self.app.fsignals.on_release(fid, data, data["tickers"])
        elif item["event"] == "mna":
            await self.app.fsignals.mna_events(f"fin:{fid}", data["title"], data["tickers"],
                                               data.get("published") or now, {"url": data["url"]}, data["title"])
        self._recent.append({"id": fid, "ts": now, "tickers": set(tickers), "event": item["event"], "tokens": tokens})
        if seed:
            return
        msg = await self.app.poster.send(item.get("channel") or "finance", embed=render.finance_item_embed(data))
        if msg:
            await store.fin_update(fid, channel_id=msg.channel.id, message_id=msg.id)

    async def _merge(self, row: dict, match: dict, item: dict, tickers: set[str]) -> None:
        data, changed = row["data"], False
        merged = sorted(set(data["tickers"]) | tickers)
        if merged != data["tickers"]:
            data["tickers"] = merged
            match["tickers"] = set(merged)
            changed = True
        if item["kind"] == "filing":
            if all(f["url"] != item["url"] for f in data["filings"]):
                data["filings"].append({"label": item["filing_label"], "url": item["url"]})
                changed = True
        else:
            urls = {data["url"], *(a["url"] for a in data["also"])}
            sources = {data["source"], *(a["source"] for a in data["also"])}
            if item["url"] not in urls and item["source"] not in sources:
                data["also"].append({"source": item["source"], "url": item["url"]})
                changed = True
        if changed and data.get("event") == "mna":
            await self.app.fsignals.mna_events(f"fin:{row['id']}", f"{data['title']}. {data.get('summary') or ''}",
                                               merged, data.get("published") or time.time(), {"url": data["url"]},
                                               data["title"])
        if changed:
            await self.app.store.fin_update(row["id"], data=data, tickers=merged,
                                            dirty=1 if row["message_id"] else None)

    async def ingest_feed_item(self, src, entry: dict, seed: bool) -> None:
        text = f"{entry['title']} {entry['summary']}"
        detected = self.watch.detect(text)
        if src.tickers == "watchlist":
            tickers = detected
        else:
            tickers = {t.upper() for t in src.tickers} | detected
        if not tickers:
            return
        await self.ingest({
            "tickers": tickers, "event": classify(entry["title"]), "kind": "release",
            "title": entry["title"] or entry["url"], "url": entry["url"], "source": src.name,
            "summary": entry["summary"],
            "published": entry["published"].isoformat() if entry["published"] else None,
        }, seed=seed)

    async def context_for(self, ticker: str, hours: float = 24) -> dict | None:
        rows = await self.app.store.fin_for_ticker(ticker, 1, since=time.time() - hours * 3600)
        if rows:
            d = rows[0]["data"]
            return {"title": d["title"], "url": d["url"], "source": d["source"]}
        if not self.app.cfg["secrets"].get("finnhub_api_key"):
            return None
        today = datetime.now(timezone.utc).date()
        try:
            news = await self.app.finnhub("/company-news", symbol=ticker,
                                          **{"from": (today - timedelta(days=1)).isoformat(), "to": today.isoformat()})
        except Exception as exc:
            log.warning("company news lookup for %s failed: %s", ticker, exc)
            return None
        for n in news or []:
            if ticker in self.watch.detect(n.get("headline", "")) and time.time() - (n.get("datetime") or 0) <= hours * 3600:
                return {"title": n["headline"], "url": n["url"], "source": n.get("source") or "News"}
        return None
