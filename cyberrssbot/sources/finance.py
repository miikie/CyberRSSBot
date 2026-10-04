from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timedelta, timezone

from .. import render
from ..dedup import canonical_url, key_hash
from ..finance import AMENDMENTS_KEPT, DEFAULT_FORMS, classify, describe_filing, normalize_form
from ..http import FetchError
from ..market import NY
from ..util import parse_time
from .base import Source

log = logging.getLogger(__name__)

SEC_SUBMISSIONS = "https://data.sec.gov/submissions/CIK{cik:010d}.json"
SEC_INDEX = "https://www.sec.gov/Archives/edgar/data/{cik}/{acc_path}/{acc}-index.htm"


class SECEdgarSource(Source):
    def __init__(self, app, cfg):
        super().__init__(app, cfg)
        fcfg = app.cfg["finance"]["filings"]
        self.forms = set(DEFAULT_FORMS)
        self.form4 = bool(fcfg.get("form4"))
        if fcfg.get("schedule_13g"):
            self.forms.add("SCHEDULE 13G")
        self.idle_interval = float(cfg.get("idle_interval", 3600))
        self.max_age = timedelta(days=float(cfg.get("max_age_days", 7)))
        self.lookback = timedelta(hours=float(cfg.get("first_run_lookback_hours",
                                                      app.cfg["poll"].get("first_run_lookback_hours", 0))))

    def now(self) -> datetime:
        return datetime.now(timezone.utc)

    def next_interval(self) -> float:
        ny = self.now().astimezone(NY)
        return self.interval if ny.weekday() < 5 and 6 <= ny.hour < 22 else self.idle_interval

    def _wanted(self, form: str) -> bool:
        base, amended = normalize_form(form)
        return base in self.forms and (not amended or base in AMENDMENTS_KEPT)

    async def poll(self, seed: bool) -> int:
        app = self.app
        ua = app.cfg["secrets"].get("sec_user_agent")
        if not ua:
            raise FetchError("SEC_USER_AGENT or MAIN_EMAIL is not set")
        headers = {"User-Agent": ua, "Accept": "application/json"}
        count, failures = 0, []
        for ticker, info in app.finance.watch.companies.items():
            if not info.get("cik"):
                continue
            cik = int(info["cik"])
            try:
                fetched = await app.http.get(SEC_SUBMISSIONS.format(cik=cik), headers=headers, conditional=False)
                count += await self._process(ticker, cik, json.loads(fetched.body), seed)
            except FetchError as exc:
                failures.append(f"{ticker}: {exc}")
        if failures and len(failures) == len([i for i in app.finance.watch.companies.values() if i.get("cik")]):
            raise FetchError("; ".join(failures)[:280])
        if failures:
            log.warning("sec_edgar partial failure: %s", "; ".join(failures))
        return count

    async def _process(self, ticker: str, cik: int, data: dict, seed: bool) -> int:
        store = self.app.store
        recent = data.get("filings", {}).get("recent", {})
        rows = list(zip(recent.get("accessionNumber", []), recent.get("form", []), recent.get("items", []),
                        recent.get("acceptanceDateTime", []), recent.get("filingDate", []),
                        recent.get("primaryDocument", []) or [""] * len(recent.get("form", []))))
        now = self.now()
        count = 0
        for acc, form, items, accepted, filed, primary in reversed(rows[:60]):
            when = parse_time(accepted) or parse_time(filed)
            if not when or now - when > self.max_age:
                continue
            key = "sec:" + acc
            if await store.seen_any([key]):
                continue
            await store.mark_seen([key], self.id)
            base_form = normalize_form(form)[0]
            index_url = SEC_INDEX.format(cik=cik, acc_path=acc.replace("-", ""), acc=acc)
            if base_form == "8-K" and "2.02" in (items or "").split(","):
                event_id, created = await self.app.events.record(
                    "earnings.report", ticker=ticker, cik=cik, company=self.app.finance.watch.name(ticker),
                    occurred_at=when, dedup=acc, payload={"items": items}, refs={"accession": acc, "filing": index_url})
                if created:
                    await self.app.fsignals.on_earnings(event_id)
            if base_form == "SCHEDULE 13D":
                await self.app.fsignals.on_13d(ticker, cik, acc, form, when, index_url)
            if base_form == "4":
                if self.form4 and primary:
                    try:
                        await self.app.fsignals.on_form4(ticker, cik, acc, primary, when,
                                                         post=not seed or bool(self.lookback and now - when <= self.lookback))
                    except (FetchError, ValueError) as exc:
                        log.warning("form 4 %s for %s skipped: %s", acc, ticker, exc)
                continue
            if not self._wanted(form):
                continue
            described = describe_filing(form, items)
            if described is None:
                continue
            event, label = described
            base, amended = normalize_form(form)
            shown = base + ("/A" if amended else "")
            name = self.app.finance.watch.name(ticker)
            quiet = seed and not (self.lookback and now - when <= self.lookback)
            await self.app.finance.ingest({
                "tickers": {ticker}, "event": event, "kind": "filing",
                "title": f"{name} files {shown}: {label}",
                "filing_label": f"{shown} · {label}",
                "url": SEC_INDEX.format(cik=cik, acc_path=acc.replace("-", ""), acc=acc),
                "source": "SEC EDGAR", "summary": "", "published": when.isoformat(), "channel": self.channel,
            }, seed=quiet)
            count += 1
        return count


class QuotesSource(Source):
    seed_on_first_run = False

    def __init__(self, app, cfg):
        super().__init__(app, cfg)
        f = app.cfg["finance"]
        self.pct = float(f["move_alert_pct"])
        self.delay = timedelta(minutes=float(f["summary_delay_minutes"]))
        self.summary_grace = timedelta(hours=float(f.get("summary_grace_hours", 4)))

    def now(self) -> datetime:
        return datetime.now(NY)

    def next_interval(self) -> float:
        now = self.now()
        start, close = self.app.market.next_session(now - self.delay - timedelta(minutes=1))
        summary_at = close + self.delay
        if start <= now <= close:
            return self.interval
        if close < now < summary_at:
            return max(60.0, (summary_at - now).total_seconds() + 5)
        if now < start:
            return max(60.0, min(3600.0, (start - now).total_seconds() + 5))
        return 3600.0

    async def sweep(self) -> dict[str, dict]:
        quotes, errors = {}, []
        for symbol in self.app.finance.watch.symbols():
            try:
                q = await self.app.finnhub("/quote", symbol=symbol)
            except FetchError as exc:
                errors.append(f"{symbol}: {exc}")
                continue
            if not q or not q.get("c"):
                errors.append(f"{symbol}: no data")
                continue
            quotes[symbol] = q
            await self.app.store.quote_put(symbol, q)
        if errors and not quotes:
            raise FetchError("; ".join(errors)[:280])
        return quotes

    async def poll(self, seed: bool) -> int:
        await self.app.refresh_holidays()
        if seed:
            return len(await self.sweep())
        now = self.now()
        session = self.app.market.session(now.date())
        if session is None:
            return 0
        start, close = session
        summary_at = close + self.delay
        if now < start or (close + timedelta(minutes=5) < now < summary_at) or now > summary_at + self.summary_grace:
            return 0
        quotes = await self.sweep()
        posted = 0
        if now <= close + timedelta(minutes=5):
            posted += await self.alerts(quotes, now.date())
        if now >= summary_at:
            posted += await self.summary(quotes, now.date())
        return posted

    async def alerts(self, quotes: dict[str, dict], day) -> int:
        store, posted = self.app.store, 0
        for symbol in self.app.finance.watch.companies:
            q = quotes.get(symbol)
            if not q or q.get("dp") is None:
                continue
            move = abs(float(q["dp"]))
            level = 2 if move >= 2 * self.pct else 1 if move >= self.pct else 0
            if not level:
                continue
            first, second = f"fin:alert:{day}:{symbol}:1", f"fin:alert:{day}:{symbol}:2"
            if not await store.seen_any([first]):
                keys = [first, second] if level == 2 else [first]
            elif level == 2 and not await store.seen_any([second]):
                keys = [second]
            else:
                continue
            context = await self.app.finance.context_for(symbol)
            sector = quotes.get("CIBR", {}).get("dp")
            sector = float(sector) if sector is not None else None
            explanation = await self.app.fsignals.explain(symbol, float(q["dp"]), sector, datetime.now(timezone.utc))
            embed = render.move_alert_embed(symbol, self.app.finance.watch.name(symbol), q, level, self.pct, context,
                                            explanation, self.app.poster.jump_url, sector)
            await self.app.poster.send(self.channel, embed=embed)
            await store.mark_seen(keys, self.id)
            posted += 1
        return posted

    async def summary(self, quotes: dict[str, dict], day) -> int:
        key = f"fin:summary:{day}"
        if await self.app.store.seen_any([key]) or not quotes:
            return 0
        unexplained = [(e["ticker"], float(e["payload"].get("dp") or 0))
                       for e in await self.app.store.events_query(type_="move.unexplained", since=day.isoformat(),
                                                                  until=(day + timedelta(days=7)).isoformat())
                       if parse_time(e["occurred_at"]).astimezone(NY).date() == day]
        embed = render.close_summary_embed(day, quotes, self.app.finance.watch, unexplained)
        await self.app.poster.send(self.channel, embed=embed)
        await self.app.store.mark_seen([key], self.id)
        return 1


class EarningsSource(Source):
    seed_on_first_run = False

    def __init__(self, app, cfg):
        super().__init__(app, cfg)
        f = app.cfg["finance"]["earnings"]
        self.weekday = int(f.get("weekly_weekday", 0))
        self.weekly_hour = int(f.get("weekly_hour_utc", 13))
        self.reminder = bool(f.get("same_day_reminder", True))
        self.reminder_hour = int(f.get("reminder_hour_et", 8))
        self.refresh = float(f.get("refresh_hours", 12)) * 3600
        self.horizon = int(f.get("horizon_days", 90))
        self._refreshed = 0.0

    def now(self) -> datetime:
        return datetime.now(timezone.utc)

    async def refresh_calendar(self) -> int:
        today = self.now().date()
        start = (today - timedelta(days=1)).isoformat()
        end = (today + timedelta(days=self.horizon)).isoformat()
        total, errors = 0, []
        for symbol in self.app.finance.watch.companies:
            try:
                data = await self.app.finnhub("/calendar/earnings", symbol=symbol, **{"from": start, "to": end})
            except FetchError as exc:
                errors.append(f"{symbol}: {exc}")
                continue
            rows = [r for r in (data or {}).get("earningsCalendar") or [] if r.get("symbol", "").upper() == symbol]
            await self.app.store.earnings_replace(symbol, rows, start)
            total += len(rows)
        if errors and len(errors) == len(self.app.finance.watch.companies):
            raise FetchError("; ".join(errors)[:280])
        self._refreshed = time.time()
        return total

    async def poll(self, seed: bool) -> int:
        if seed or time.time() - self._refreshed >= self.refresh:
            total = await self.refresh_calendar()
            if seed:
                return total
        return await self.weekly() + await self.same_day()

    async def weekly(self) -> int:
        now = self.now()
        if now.weekday() != self.weekday or now.hour < self.weekly_hour:
            return 0
        iso = now.isocalendar()
        key = f"fin:weekly:{iso[0]}-W{iso[1]:02d}"
        if await self.app.store.seen_any([key]):
            return 0
        start = now.date()
        rows = await self.app.store.earnings_between(start.isoformat(), (start + timedelta(days=6)).isoformat())
        embed = render.earnings_embed(rows, self.app.finance.watch, "Earnings this week",
                                      empty="No watchlist companies report this week.")
        await self.app.poster.send(self.channel, embed=embed)
        await self.app.store.mark_seen([key], self.id)
        return 1

    async def same_day(self) -> int:
        if not self.reminder:
            return 0
        ny = self.now().astimezone(NY)
        if ny.hour < self.reminder_hour:
            return 0
        key = f"fin:reminder:{ny.date()}"
        if await self.app.store.seen_any([key]):
            return 0
        rows = await self.app.store.earnings_between(ny.date().isoformat(), ny.date().isoformat())
        await self.app.store.mark_seen([key], self.id)
        if not rows:
            return 0
        embed = render.earnings_embed(rows, self.app.finance.watch, "Reporting today")
        await self.app.poster.send(self.channel, embed=embed)
        return 1


class CompanyNewsSource(Source):
    async def poll(self, seed: bool) -> int:
        app = self.app
        today = datetime.now(timezone.utc).date()
        lookback = timedelta(hours=float(self.cfg.get("first_run_lookback_hours",
                                                      app.cfg["poll"].get("first_run_lookback_hours", 0))))
        count, errors = 0, []
        for symbol in app.finance.watch.companies:
            try:
                news = await app.finnhub("/company-news", symbol=symbol,
                                         **{"from": (today - timedelta(days=1)).isoformat(), "to": today.isoformat()})
            except FetchError as exc:
                errors.append(f"{symbol}: {exc}")
                continue
            for n in sorted(news or [], key=lambda x: x.get("datetime") or 0):
                url, headline = n.get("url"), n.get("headline") or ""
                if not url:
                    continue
                key = "u:" + key_hash(canonical_url(url))
                if await app.store.seen_any([key]):
                    continue
                await app.store.mark_seen([key], self.id)
                if symbol not in app.finance.watch.detect(headline):
                    continue
                published = datetime.fromtimestamp(n.get("datetime") or 0, timezone.utc)
                quiet = seed and not (lookback and datetime.now(timezone.utc) - published <= lookback)
                await app.finance.ingest({
                    "tickers": {symbol} | app.finance.watch.detect(headline), "event": classify(headline),
                    "kind": "news", "title": headline, "url": url, "source": n.get("source") or "News",
                    "summary": n.get("summary") or "", "published": published.isoformat(),
                }, seed=quiet)
                count += 1
        if errors and len(errors) == len(app.finance.watch.companies):
            raise FetchError("; ".join(errors)[:280])
        return count
