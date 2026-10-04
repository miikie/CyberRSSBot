from __future__ import annotations

import bisect
import math
import random
import statistics
from dataclasses import dataclass, field

WINDOWS = {"car_0_1": (0, 1), "car_0_5": (0, 5), "car_0_20": (0, 20), "pre_5": (-5, -1)}
WINDOW_BY_DAYS = {1: "car_0_1", 5: "car_0_5", 20: "car_0_20"}
ESTIMATION = (-130, -11)
MIN_ESTIMATION = 60
OVERLAP_SESSIONS = 20
MIN_N = 20
BOOTSTRAP = 2000
SEED = 20231218


def daily_returns(rows: list[dict]) -> dict[str, float]:
    out, prev = {}, None
    for row in rows:
        price = row.get("adj_close")
        if price is not None and price > 0 and prev is not None and prev > 0:
            out[row["date"]] = price / prev - 1
        prev = price if price is not None and price > 0 else None
    return out


def _ols(xs: list[float], ys: list[float]) -> tuple[float, float]:
    mx, my = statistics.fmean(xs), statistics.fmean(ys)
    var = sum((x - mx) ** 2 for x in xs)
    beta = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / var if var else 0.0
    return my - beta * mx, beta


def event_car(session: str, stock: dict[str, float], bench: dict[str, float], calendar: list[str]) -> dict:
    idx = bisect.bisect_left(calendar, session)
    out = {"windows": {}, "complete": True}
    if idx >= len(calendar):
        return {"windows": {}, "complete": False, "status": "pending"}
    est = [calendar[i] for i in range(max(0, idx + ESTIMATION[0]), max(0, idx + ESTIMATION[1] + 1))]
    pairs = [(bench[d], stock[d]) for d in est if d in bench and d in stock]
    model = _ols([p[0] for p in pairs], [p[1] for p in pairs]) if len(pairs) >= MIN_ESTIMATION else None
    out["estimation_n"] = len(pairs)
    for name, (a, b) in WINDOWS.items():
        lo, hi = idx + a, idx + b
        if lo < 0:
            out["windows"][name] = {"status": "missing"}
            continue
        if hi >= len(calendar):
            out["windows"][name] = {"status": "pending"}
            out["complete"] = False
            continue
        days = calendar[lo:hi + 1]
        if any(d not in stock or d not in bench for d in days):
            out["windows"][name] = {"status": "missing"}
            continue
        ma = sum(stock[d] - bench[d] for d in days)
        entry = {"status": "ok", "ma": round(ma, 6)}
        if model:
            alpha, beta = model
            entry["mm"] = round(sum(stock[d] - (alpha + beta * bench[d]) for d in days), 6)
        out["windows"][name] = entry
    return out


@dataclass
class Summary:
    n: int
    mean: float | None = None
    median: float | None = None
    share_negative: float | None = None
    share_positive: float | None = None
    t_stat: float | None = None
    ci: tuple[float, float] | None = None
    insufficient: bool = True
    values: list[float] = field(default_factory=list, repr=False)


def summarize(values: list[float], *, seed: int = SEED, resamples: int = BOOTSTRAP) -> Summary:
    n = len(values)
    if not n:
        return Summary(0)
    mean = statistics.fmean(values)
    sd = statistics.stdev(values) if n > 1 else 0.0
    t = mean / (sd / math.sqrt(n)) if sd > 0 else None
    rng = random.Random(seed)
    means = sorted(statistics.fmean(rng.choices(values, k=n)) for _ in range(resamples)) if n > 1 else [mean]
    lo = means[int(0.025 * (len(means) - 1))]
    hi = means[int(math.ceil(0.975 * (len(means) - 1)))]
    return Summary(n, mean, statistics.median(values), sum(v < 0 for v in values) / n,
                   sum(v > 0 for v in values) / n, t, (lo, hi), n < MIN_N, list(values))


def drop_overlaps(events: list[dict], calendar: list[str]) -> tuple[list[dict], int]:
    kept, last, dropped = [], {}, 0
    for ev in sorted(events, key=lambda e: (e["effective_session"], e["occurred_at"], e["id"])):
        idx = bisect.bisect_left(calendar, ev["effective_session"])
        prev = last.get(ev["ticker"])
        if prev is not None and idx - prev < OVERLAP_SESSIONS:
            dropped += 1
            continue
        last[ev["ticker"]] = idx
        kept.append(ev)
    return kept, dropped


class Study:
    def __init__(self, app):
        self.app = app
        self._series: dict[str, dict[str, float]] = {}

    async def series(self, symbol: str) -> dict[str, float]:
        if symbol not in self._series:
            self._series[symbol] = daily_returns(await self.app.store.prices_for(symbol))
        return self._series[symbol]

    def reset(self) -> None:
        self._series.clear()

    async def calendar(self) -> list[str]:
        return [r["date"] for r in await self.app.store.prices_for("SPY")]

    async def returns_for(self, event: dict, calendar: list[str]) -> dict | None:
        if not event["ticker"]:
            return None
        cached = await self.app.store.event_return_get(event["id"])
        if cached and cached.get("complete"):
            return cached
        bench_symbol = self.app.companies.benchmark(event["ticker"])
        stock = await self.series(event["ticker"])
        if not stock:
            return {"windows": {}, "complete": False, "status": "no prices", "benchmark": bench_symbol}
        result = event_car(event["effective_session"], stock, await self.series(bench_symbol), calendar)
        result["benchmark"] = bench_symbol
        if result.get("complete"):
            await self.app.store.event_return_put(event["id"], result)
        return result

    async def aggregate(self, type_: str, window: str, *, ticker: str | None = None, feature: str | None = None,
                        min_confidence: float = 0.0, method: str = "ma") -> dict:
        calendar = await self.calendar()
        events = [e for e in await self.app.store.events_query(type_=type_, ticker=ticker)
                  if e["ticker"] and (e["confidence"] or 0) >= min_confidence
                  and (feature is None or (e["payload"].get("features") or {}).get(feature))]
        main = [e for e in events if e["session_timing"] != "intraday"]
        intraday = [e for e in events if e["session_timing"] == "intraday"]
        out = {"type": type_, "window": window, "method": method, "events": len(events)}
        for label, group in (("main", main), ("intraday", intraday)):
            kept, dropped = drop_overlaps(group, calendar)
            values, skipped, pending = [], 0, 0
            for ev in kept:
                result = await self.returns_for(ev, calendar)
                entry = ((result or {}).get("windows") or {}).get(window) or {}
                if entry.get("status") == "ok" and entry.get(method) is not None:
                    values.append(entry[method])
                elif entry.get("status") == "pending":
                    pending += 1
                else:
                    skipped += 1
            out[label] = {"summary": summarize(values), "overlap_dropped": dropped, "skipped": skipped,
                          "pending": pending}
        return out
