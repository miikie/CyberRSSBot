from __future__ import annotations

import logging
from datetime import date, datetime, timedelta, timezone

from bs4 import BeautifulSoup

from . import guidance, insiders, render, signals
from .http import FetchError
from .incidents import filing_text
from .market import NY
from .tone import Lexicon, shift
from .util import parse_time

log = logging.getLogger(__name__)

SEC_ARCHIVE = "https://www.sec.gov/Archives/edgar/data/{cik}/{acc_path}/"
ATTRIBUTION_DEFAULTS = {
    "lookback_hours": 72, "half_life_hours": 24, "sector_share": 0.4, "default_weight": 1.0,
    "type_weights": {
        "sec.8k.1_05": 5, "sec.8k.1_05_amendment": 3, "sec.8k.8_01_cyber": 3, "earnings.report": 5, "mna.announce": 5,
        "guidance.raise": 4, "guidance.cut": 4, "guidance.reaffirm": 2, "strategic.review": 4, "ownership.13d": 3,
        "insider.open_buy": 2, "insider.cluster_sell": 2, "tone.shift": 2, "pressure.spike": 2,
        "ransomware.claim.public": 3, "breach.news.public": 3, "kev.vendor": 1, "vuln.vendor_critical": 1,
    },
}


def _headers(app, accept="text/html,application/xhtml+xml"):
    ua = app.cfg["secrets"].get("sec_user_agent")
    if not ua:
        raise FetchError("SEC_USER_AGENT or MAIN_EMAIL is not set")
    return {"User-Agent": ua, "Accept": accept}


def exhibit_url(index_html: bytes, base: str, wanted=("EX-99.1", "EX-99")) -> str | None:
    soup = BeautifulSoup(index_html, "html.parser")
    rows = []
    for row in soup.select("table.tableFile tr"):
        cells = row.find_all("td")
        if len(cells) >= 4 and cells[2].find("a"):
            rows.append((cells[3].get_text(strip=True).upper(), cells[2].find("a").get("href", "")))
    for kind in wanted:
        for doc_type, href in rows:
            if doc_type == kind:
                from urllib.parse import urljoin
                return urljoin(base, href.replace("/ix?doc=", ""))
    return None


class FinanceSignals:
    def __init__(self, app):
        self.app = app
        cfg = app.cfg.get("signals") or {}
        self.attribution = {**ATTRIBUTION_DEFAULTS, **(cfg.get("attribution") or {})}
        self.attribution["type_weights"] = {**ATTRIBUTION_DEFAULTS["type_weights"],
                                            **((cfg.get("attribution") or {}).get("type_weights") or {})}
        self.lexicon = Lexicon(app.kb.extras_dir / "lexicon")
        self.filings_channel = "finance-filings"
        self.signals_channel = "finance-signals"

    # ---- press releases and news ---------------------------------------------------------------
    async def on_release(self, fid: int, data: dict, tickers) -> None:
        text = f"{data['title']}. {data.get('summary') or ''}"
        when = data.get("published") or datetime.now(timezone.utc).isoformat()
        refs = {"url": data["url"], "fin": fid}
        for kind in guidance.guidance(text):
            for ticker in tickers:
                await self.app.events.record(kind, ticker=ticker, occurred_at=when, dedup=f"fin:{fid}", refs=refs,
                                             payload={"title": data["title"], "source": data.get("source")})
        if guidance.strategic_review(text):
            for ticker in tickers:
                await self.app.events.record("strategic.review", ticker=ticker, occurred_at=when, dedup=f"fin:{fid}",
                                             refs=refs, payload={"title": data["title"]})
        if data.get("event") == "mna" or guidance.mna(text):
            await self.mna_events(f"fin:{fid}", text, tickers, when, refs, data["title"])

    async def mna_events(self, dedup: str, text: str, tickers, when, refs: dict, title: str) -> None:
        found = guidance.mna(text)
        counter = self.app.companies.resolve(found["counterparty"]) if found and found.get("counterparty") else None
        opposite = {"acquirer": "target", "target": "acquirer"}
        roles = {}
        for ticker in tickers:
            if not found:
                roles[ticker] = "unknown"
            elif counter and counter.ticker == ticker:
                roles[ticker] = opposite[found["role"]]
            else:
                roles[ticker] = found["role"]
        if found and counter and counter.ticker not in roles and counter.confidence >= 1.0:
            roles[counter.ticker] = opposite[found["role"]]
        for ticker, role in sorted(roles.items()):
            payload = {"title": title, "role": role, "counterparty": (found or {}).get("counterparty")}
            event_id, created = await self.app.events.record("mna.announce", ticker=ticker, occurred_at=when,
                                                             dedup=dedup, refs=refs, payload=payload)
            if not created and role != "unknown":
                existing = await self.app.store.event_get(event_id)
                if existing["payload"].get("role") in (None, "unknown"):
                    await self.app.store.event_set_payload(event_id, {**existing["payload"], **payload})

    # ---- earnings releases (8-K exhibit 99.1) ------------------------------------------------------
    async def exhibit_text(self, cik: int, accession: str) -> tuple[str | None, str | None]:
        base = SEC_ARCHIVE.format(cik=cik, acc_path=accession.replace("-", ""))
        index = await self.app.http.get(base + f"{accession}-index.htm", headers=_headers(self.app), conditional=False)
        url = exhibit_url(index.body, base)
        if not url:
            return None, None
        doc = await self.app.http.get(url, headers=_headers(self.app), conditional=False)
        return filing_text(doc.body), url

    async def on_earnings(self, event_id: int) -> None:
        store = self.app.store
        ev = await store.event_get(event_id)
        if not ev or ev["payload"].get("tone") or not ev["cik"] or not ev["source_refs"].get("accession"):
            return
        try:
            text, url = await self.exhibit_text(ev["cik"], ev["source_refs"]["accession"])
        except Exception as exc:
            log.info("exhibit for %s %s unavailable: %s", ev["ticker"], ev["source_refs"]["accession"], exc)
            return
        if not text:
            await self._payload(event_id, {"tone": None, "exhibit": None})
            return
        tone = self.lexicon.score(text)
        await self._payload(event_id, {"tone": tone, "exhibit": url})
        prior = [e["payload"]["tone"]["tone"] for e in await store.events_query(type_="earnings.report", ticker=ev["ticker"],
                                                                               until=ev["effective_session"])
                 if e["id"] != event_id and (e["payload"].get("tone") or {}).get("tone") is not None
                 and (e["effective_session"], e["id"]) < (ev["effective_session"], ev["id"])]
        moved = shift(tone["tone"], prior)
        if moved:
            await self.app.events.record("tone.shift", ticker=ev["ticker"], cik=ev["cik"], company=ev["company"],
                                         occurred_at=ev["occurred_at"], dedup=ev["dedup_key"],
                                         refs={**ev["source_refs"], "exhibit": url}, payload={"tone": tone, **moved})
        refs = {**ev["source_refs"], "exhibit": url}
        for kind in guidance.guidance(text):
            await self.app.events.record(kind, ticker=ev["ticker"], cik=ev["cik"], company=ev["company"],
                                         occurred_at=ev["occurred_at"], dedup=ev["dedup_key"], refs=refs,
                                         payload={"source": "8-K exhibit 99.1"})
        if guidance.strategic_review(text):
            await self.app.events.record("strategic.review", ticker=ev["ticker"], cik=ev["cik"],
                                         occurred_at=ev["occurred_at"], dedup=ev["dedup_key"], refs=refs, payload={})

    async def _payload(self, event_id: int, extra: dict) -> None:
        ev = await self.app.store.event_get(event_id)
        await self.app.store.event_set_payload(event_id, {**ev["payload"], **extra})

    # ---- Form 4 and Schedule 13D ----------------------------------------------------------------------
    async def on_form4(self, ticker: str, cik: int, accession: str, primary_doc: str, accepted, *,
                       post: bool) -> list[int]:
        xml_name = primary_doc.split("/")[-1]
        url = SEC_ARCHIVE.format(cik=cik, acc_path=accession.replace("-", "")) + xml_name
        fetched = await self.app.http.get(url, headers=_headers(self.app, "application/xml,text/xml"), conditional=False)
        form = insiders.parse_form4(fetched.body)
        owner = form["owners"][0] if form["owners"] else {"cik": "", "name": "unknown", "roles": []}
        rows = []
        for i, tx in enumerate(form["transactions"]):
            rows.append({"accession": accession, "idx": i, "ticker": ticker, "owner_cik": owner["cik"],
                         "owner": owner["name"], "role": ", ".join(owner["roles"]), **tx})
        await self.app.store.insider_put(rows)
        created_ids = []
        index_url = SEC_ARCHIVE.format(cik=cik, acc_path=accession.replace("-", "")) + f"{accession}-index.htm"
        buys = insiders.open_market_buys(form)
        if buys:
            value = round(sum(b["value"] or 0 for b in buys), 2)
            event_id, created = await self.app.events.record(
                "insider.open_buy", ticker=ticker, cik=cik, occurred_at=accepted, dedup=accession,
                refs={"filing": index_url, "accession": accession},
                payload={"owner": owner["name"], "role": ", ".join(owner["roles"]), "value": value,
                         "shares": sum(b["shares"] or 0 for b in buys), "price": buys[0]["price"]})
            if created:
                created_ids.append(event_id)
        if insiders.unplanned_sales(form):
            event_id = await self.check_cluster(ticker, cik, accepted, index_url)
            if event_id:
                created_ids.append(event_id)
        if post:
            for event_id in created_ids:
                await self.post_insider(event_id)
        return created_ids

    async def check_cluster(self, ticker: str, cik: int, accepted, index_url: str) -> int | None:
        when = accepted if isinstance(accepted, datetime) else parse_time(str(accepted))
        day = when.astimezone(NY).date()
        calendar = insiders.trading_days(day - timedelta(days=30), day, self.app.market)
        sales = await self.app.store.insider_sales(ticker, calendar[0] if calendar else day.isoformat(), day.isoformat())
        found = insiders.cluster(sales, day.isoformat(), calendar)
        if not found:
            return None
        recent = [e for e in await self.app.store.events_query(type_="insider.cluster_sell", ticker=ticker)
                  if e["payload"].get("end", "") >= calendar[max(0, len(calendar) - insiders.CLUSTER_SESSIONS)]]
        if recent:
            return None
        event_id, created = await self.app.events.record(
            "insider.cluster_sell", ticker=ticker, cik=cik, occurred_at=when, dedup=f"{found['start']}:{found['end']}",
            refs={"filing": index_url}, payload=found)
        return event_id if created else None

    async def post_insider(self, event_id: int) -> None:
        ev = await self.app.store.event_get(event_id)
        msg = await self.app.poster.send(self.filings_channel, embed=render.insider_embed(ev))
        if msg:
            await self.app.events.add_refs(event_id, {"message": [msg.channel.id, msg.id]})

    async def on_13d(self, ticker: str, cik: int, accession: str, form: str, accepted, url: str) -> None:
        await self.app.events.record("ownership.13d", ticker=ticker, cik=cik, occurred_at=accepted, dedup=accession,
                                     refs={"filing": url, "accession": accession}, payload={"form": form})

    # ---- vulnerability pressure --------------------------------------------------------------------------
    async def pressure(self, day: date, *, post: bool) -> list[tuple[str, dict]]:
        s = signals.settings(self.app.cfg)
        contribs = await signals.contributions(self.app)
        ranked = signals.ranking(contribs, day, s)
        when = signals.close_time(day, self.app.market)
        for ticker, p in ranked:
            if not p["spike"]:
                continue
            event_id, created = await self.app.events.record(
                "pressure.spike", ticker=ticker, occurred_at=when, dedup=day.isoformat(),
                payload={"score": p["score"], "z": p["z"], "items": p["items"],
                         "top": [{"title": c.title, "url": c.url, "kind": c.kind} for c in p["top"]]})
            if created and post:
                ev = await self.app.store.event_get(event_id)
                msg = await self.app.poster.send(self.signals_channel, embed=render.pressure_spike_embed(ev))
                if msg:
                    await self.app.events.add_refs(event_id, {"message": [msg.channel.id, msg.id]})
        return ranked

    async def pressure_history(self, start: date, end: date) -> int:
        s = signals.settings(self.app.cfg)
        contribs = await signals.contributions(self.app)
        coverage = signals.coverage_start(contribs)
        if coverage is None:
            return 0
        count = 0
        for ticker, items in signals.by_ticker(contribs).items():
            for day, p in signals.spike_days(items, max(start, coverage), end, coverage, s):
                _, created = await self.app.events.record(
                    "pressure.spike", ticker=ticker, occurred_at=signals.close_time(day, self.app.market),
                    dedup=day.isoformat(), payload={"score": p["score"], "z": p["z"], "items": p["items"],
                                                    "top": [{"title": c.title, "url": c.url, "kind": c.kind}
                                                            for c in p["top"]]})
                count += int(created)
        return count

    # ---- move attribution ----------------------------------------------------------------------------------
    async def catalysts(self, ticker: str, now: datetime) -> list[tuple[float, dict]]:
        a = self.attribution
        since = (now - timedelta(hours=a["lookback_hours"])).astimezone(NY).date().isoformat()
        ranked = []
        for ev in await self.app.store.events_query(ticker=ticker, since=since):
            occurred = parse_time(ev["occurred_at"])
            if occurred is None or occurred > now:
                continue
            hours = (now - occurred).total_seconds() / 3600
            if hours > a["lookback_hours"] or ev["type"] == "move.unexplained":
                continue
            weight = float(a["type_weights"].get(ev["type"], a["default_weight"]))
            ranked.append((round(weight * 0.5 ** (hours / a["half_life_hours"]), 4), ev))
        return sorted(ranked, key=lambda r: (-r[0], -r[1]["id"]))

    def classify_move(self, dp: float, sector_dp: float | None) -> str:
        if sector_dp is None or dp == 0:
            return "idiosyncratic"
        return "with sector" if abs(dp - sector_dp) < self.attribution["sector_share"] * abs(dp) else "idiosyncratic"

    async def explain(self, ticker: str, dp: float, sector_dp: float | None, now: datetime) -> dict:
        found = await self.catalysts(ticker, now)
        kind = self.classify_move(dp, sector_dp)
        result = {"classification": kind, "catalysts": [ev for _, ev in found[:3]], "unexplained": False}
        if kind == "idiosyncratic" and not found:
            result["unexplained"] = True
            await self.app.events.record("move.unexplained", ticker=ticker, occurred_at=now,
                                         dedup=now.astimezone(NY).date().isoformat(),
                                         payload={"dp": dp, "sector_dp": sector_dp})
        return result
