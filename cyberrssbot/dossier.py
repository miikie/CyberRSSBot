from __future__ import annotations

import bisect
from datetime import date, datetime, timedelta, timezone

from . import signals
from .market import NY

EARNINGS_SHOWN = 8
TONE_SHOWN = 4
TIMELINE_DAYS = 90
OWNERSHIP_TYPES = ("insider.open_buy", "insider.cluster_sell", "ownership.13d")


def _price_on_or_before(rows: list[dict], day: str) -> float | None:
    dates = [r["date"] for r in rows]
    i = bisect.bisect_right(dates, day) - 1
    return rows[i]["adj_close"] if i >= 0 else None


def relative(stock: list[dict], bench: list[dict], days: int, today: date) -> dict | None:
    if not stock or not bench:
        return None
    end = stock[-1]["date"]
    start = (date.fromisoformat(end) - timedelta(days=days)).isoformat()
    s0, s1 = _price_on_or_before(stock, start), stock[-1]["adj_close"]
    b0, b1 = _price_on_or_before(bench, start), _price_on_or_before(bench, end)
    if not all((s0, s1, b0, b1)):
        return None
    return {"stock": s1 / s0 - 1, "bench": b1 / b0 - 1, "relative": (s1 / s0) - (b1 / b0), "as_of": end}


async def build(app, ticker: str, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    today = now.astimezone(NY).date()
    ticker = ticker.upper()
    store, studies = app.store, app.study
    calendar = await studies.calendar()
    name = app.finance.watch.name(ticker) if ticker in app.finance.watch.companies else \
        (app.companies.by_ticker_company(ticker).name if app.companies.by_ticker_company(ticker) else ticker)

    upcoming = [r for r in await store.earnings_between(today.isoformat(), (today + timedelta(days=120)).isoformat())
                if r.get("symbol") == ticker]
    earnings = (await store.events_query(type_="earnings.report", ticker=ticker))[-EARNINGS_SHOWN:]
    reactions = []
    for ev in reversed(earnings):
        result = await studies.returns_for(ev, calendar) or {}
        windows = result.get("windows") or {}
        reactions.append({"session": ev["effective_session"], "timing": ev["session_timing"],
                          "car_0_1": (windows.get("car_0_1") or {}).get("ma"),
                          "car_0_5": (windows.get("car_0_5") or {}).get("ma"),
                          "tone": (ev["payload"].get("tone") or {}).get("tone"),
                          "link": ev["payload"].get("exhibit") or ev["source_refs"].get("exhibit")
                                  or ev["source_refs"].get("filing")})
    since = (today - timedelta(days=TIMELINE_DAYS)).isoformat()
    timeline = await store.events_query(ticker=ticker, since=since)

    s = signals.settings(app.cfg)
    contribs = [c for c in await signals.contributions(app) if c.ticker == ticker]
    pressure = None
    if contribs:
        everything = await signals.contributions(app)
        pressure = signals.pressure_on(contribs, today, signals.coverage_start(everything), s)

    bench_symbol = app.companies.benchmark(ticker)
    stock_rows = await store.prices_for(ticker)
    bench_rows = await store.prices_for("CIBR")
    performance = {days: relative(stock_rows, bench_rows, days, today) for days in (30, 90)}

    evidence = []
    for type_ in sorted({e["type"] for e in timeline}):
        result = await studies.aggregate(type_, "car_0_5")
        summary = result["main"]["summary"]
        evidence.append({"type": type_, "n": summary.n, "mean": summary.mean, "median": summary.median,
                         "ci": summary.ci, "insufficient": summary.insufficient})

    return {
        "ticker": ticker, "name": name, "as_of": today.isoformat(), "benchmark": bench_symbol,
        "next_earnings": upcoming[0] if upcoming else None,
        "reactions": reactions,
        "tone": [r for r in reactions if r["tone"] is not None][:TONE_SHOWN],
        "timeline": timeline,
        "ownership": [e for e in timeline if e["type"] in OWNERSHIP_TYPES],
        "pressure": pressure,
        "performance": performance,
        "evidence": evidence,
    }


def sessions_before(day: date, count: int, calendar) -> date:
    d = day
    seen = 0
    while seen < count:
        d -= timedelta(days=1)
        if calendar.is_trading_day(d):
            seen += 1
    return d
