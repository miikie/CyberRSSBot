from __future__ import annotations

import json
import logging
from datetime import date, datetime, timedelta, timezone

from .http import FetchError
from .market import NY, MarketCalendar

log = logging.getLogger(__name__)

YAHOO_CHART = "https://query1.finance.yahoo.com/v8/finance/chart/{symbol}"
SOURCE = "yahoo"
BENCHMARKS = ("CIBR", "SPY")
JUMP_LIMIT = 0.5


def yahoo_symbol(ticker: str) -> str:
    return ticker.upper().replace(".", "-").replace("/", "-")


def parse_chart(body: bytes) -> tuple[list[dict], list[tuple[str, float]]]:
    data = json.loads(body)
    result = ((data.get("chart") or {}).get("result") or [None])[0]
    if not result:
        error = ((data.get("chart") or {}).get("error") or {}).get("description") or "no data"
        raise FetchError(f"Yahoo: {error}")
    stamps = result.get("timestamp") or []
    offset = int((result.get("meta") or {}).get("gmtoffset") or 0)
    quote = ((result.get("indicators") or {}).get("quote") or [{}])[0]
    adj = (((result.get("indicators") or {}).get("adjclose") or [{}])[0]).get("adjclose") or []
    rows = []
    for i, stamp in enumerate(stamps):
        day = datetime.fromtimestamp(stamp + offset, timezone.utc).date().isoformat()

        def pick(key, i=i):
            values = quote.get(key) or []
            return values[i] if i < len(values) else None
        close, adj_close = pick("close"), adj[i] if i < len(adj) else None
        if close is None and adj_close is None:
            continue
        rows.append({"date": day, "open": pick("open"), "high": pick("high"), "low": pick("low"), "close": close,
                     "adj_close": adj_close if adj_close is not None else close, "volume": pick("volume")})
    splits = []
    for event in ((result.get("events") or {}).get("splits") or {}).values():
        day = datetime.fromtimestamp(int(event["date"]) + offset, timezone.utc).date().isoformat()
        ratio = float(event.get("numerator") or 1) / float(event.get("denominator") or 1)
        splits.append((day, ratio))
    deduped = {}
    for row in rows:
        deduped[row["date"]] = row
    return [deduped[d] for d in sorted(deduped)], sorted(splits)


async def fetch(http, ticker: str, years: float | None = None, days: int | None = None) -> tuple[list[dict], list]:
    if days is not None:
        rng = f"{max(days, 5)}d" if days <= 59 else f"{max(1, round(days / 30))}mo"
    else:
        rng = f"{int(years or 3)}y"
    fetched = await http.get(YAHOO_CHART.format(symbol=yahoo_symbol(ticker)),
                             params={"range": rng, "interval": "1d", "events": "div,split"},
                             headers={"Accept": "application/json", "User-Agent": "Mozilla/5.0"}, conditional=False)
    return parse_chart(fetched.body)


def quality_flags(symbol: str, rows: list[dict], splits: dict[str, float], calendar: MarketCalendar,
                  today: date | None = None) -> list[str]:
    flags = []
    if not rows:
        return [f"{symbol}: no prices"]
    have = {r["date"] for r in rows}
    first, last = date.fromisoformat(rows[0]["date"]), date.fromisoformat(rows[-1]["date"])
    missing = []
    day = first
    while day <= last:
        if calendar.is_trading_day(day) and day.isoformat() not in have:
            missing.append(day.isoformat())
        day += timedelta(days=1)
    if missing:
        flags.append(f"{symbol}: {len(missing)} missing session{'s' if len(missing) != 1 else ''} "
                     f"({', '.join(missing[:3])}{'…' if len(missing) > 3 else ''})")
    extra = [r["date"] for r in rows if not calendar.is_trading_day(date.fromisoformat(r["date"]))]
    if extra:
        flags.append(f"{symbol}: {len(extra)} row(s) on non-trading days ({', '.join(extra[:3])})")
    bad = [r["date"] for r in rows if any(r.get(k) is not None and r[k] <= 0
                                          for k in ("open", "high", "low", "close", "adj_close"))]
    if bad:
        flags.append(f"{symbol}: zero or negative prices on {', '.join(bad[:3])}")
    for prev, row in zip(rows, rows[1:]):
        if prev.get("close") and row.get("close") and prev["close"] > 0:
            move = row["close"] / prev["close"] - 1
            if abs(move) > JUMP_LIMIT and row["date"] not in splits:
                flags.append(f"{symbol}: close moved {move:+.0%} on {row['date']} with no split recorded")
    if today is not None:
        stale_after = today - timedelta(days=7)
        if last < stale_after:
            flags.append(f"{symbol}: last price {last.isoformat()} is stale")
    return flags


def last_close_time(now: datetime, calendar: MarketCalendar) -> datetime:
    day = now.astimezone(NY).date()
    for _ in range(15):
        session = calendar.session(day)
        if session and session[1] <= now:
            return session[1]
        day -= timedelta(days=1)
    raise RuntimeError("no session in the last 15 days")
