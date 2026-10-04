from __future__ import annotations

import json
import math
import statistics
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone

from .market import NY
from .util import parse_time

PRESSURE_DEFAULTS = {
    "kev": 5.0, "exploited_news": 3.0, "critical_cve": 1.0, "per_outlet": 0.5, "outlet_cap": 5,
    "half_life_days": 14.0, "window_days": 30, "baseline_days": 365, "min_history_days": 90, "z_spike": 2.0,
    "min_items": 3, "weekly_weekday": 0, "weekly_hour_utc": 13, "weekly_top": 10,
}


@dataclass(frozen=True)
class Contribution:
    ticker: str
    day: date
    weight: float
    kind: str
    title: str
    url: str | None
    key: str


def settings(cfg: dict) -> dict:
    return {**PRESSURE_DEFAULTS, **(((cfg.get("signals") or {}).get("pressure")) or {})}


def _ny_day(value) -> date | None:
    when = parse_time(value) if isinstance(value, str) else value
    if when is None:
        return None
    return when.astimezone(NY).date()


def outlet_bonus(outlets: int, s: dict) -> float:
    return s["per_outlet"] * min(max(outlets, 0), int(s["outlet_cap"]))


async def contributions(app) -> list[Contribution]:
    s = settings(app.cfg)
    store, companies = app.store, app.companies
    out: list[Contribution] = []
    news_by_cve = {}
    vulns = await store._all("SELECT vid, data, first_seen FROM vulns")
    for row in vulns:
        d = json.loads(row["data"])
        news_by_cve[row["vid"]] = len(d.get("news") or [])
        ticker = companies.exposure_ticker(d.get("vendor"))
        if ticker and (d.get("cvss") or 0) >= 9:
            day = _ny_day(d.get("published")) or datetime.fromtimestamp(row["first_seen"], timezone.utc).astimezone(NY).date()
            out.append(Contribution(ticker, day, s["critical_cve"] + outlet_bonus(news_by_cve[row["vid"]], s),
                                    "critical_cve", f"{row['vid']} (CVSS {float(d['cvss']):.1f})",
                                    (d.get("refs") or {}).get("NVD"), row["vid"]))
    for ev in await store.events_query(type_="kev.vendor"):
        cve = ev["dedup_key"]
        day = _ny_day(ev["occurred_at"])
        out.append(Contribution(ev["ticker"], day, s["kev"] + outlet_bonus(news_by_cve.get(cve, 0), s), "kev",
                                f"{cve} added to KEV" + (f": {ev['payload']['name']}" if ev["payload"].get("name") else ""),
                                f"https://nvd.nist.gov/vuln/detail/{cve}", cve))
    for row in await store._all("SELECT id, ts, data FROM stories"):
        d = json.loads(row["data"])
        ex, labels = app.intel.analyze(d["title"], d.get("summary") or "", source=d["source"])
        if "exploited" not in labels:
            continue
        vendors = set(ex.entities["vendor"])
        for product in ex.entities["product"]:
            for entity in app.kb.lookup(product):
                if entity.type == "product" and entity.meta.get("vendor"):
                    vendors.add(entity.meta["vendor"])
        tickers = {companies.exposure_ticker(v) for v in vendors} - {None}
        day = datetime.fromtimestamp(row["ts"], timezone.utc).astimezone(NY).date()
        for ticker in sorted(tickers):
            out.append(Contribution(ticker, day, s["exploited_news"] + outlet_bonus(1 + len(d.get("also") or []), s),
                                    "exploited_news", d["title"], d["url"], f"story:{row['id']}"))
    return sorted(out, key=lambda c: (c.ticker, c.day, c.key, c.kind))


def score_on(contribs: list[Contribution], day: date, s: dict) -> tuple[float, list[Contribution]]:
    window = int(s["window_days"])
    half = float(s["half_life_days"])
    total, used = 0.0, []
    for c in contribs:
        age = (day - c.day).days
        if 0 <= age < window:
            total += c.weight * 0.5 ** (age / half)
            used.append(c)
    return total, used


def daily_series(contribs: list[Contribution], start: date, end: date, s: dict) -> list[float]:
    size = (end - start).days + 1
    window, half = int(s["window_days"]), float(s["half_life_days"])
    decay = [0.5 ** (age / half) for age in range(window)]
    out = [0.0] * max(size, 0)
    for c in contribs:
        offset = (c.day - start).days
        for age in range(window):
            i = offset + age
            if 0 <= i < size:
                out[i] += c.weight * decay[age]
    return out


def _z(series: list[float], i: int, first: int, s: dict) -> float | None:
    lo = max(first, i - int(s["baseline_days"]))
    history = series[lo:i]
    if len(history) < int(s["min_history_days"]):
        return None
    sd = statistics.pstdev(history)
    return (series[i] - statistics.fmean(history)) / sd if sd > 0 else None


def pressure_on(contribs: list[Contribution], day: date, coverage_start: date, s: dict) -> dict:
    score, used = score_on(contribs, day, s)
    start = max(coverage_start, day - timedelta(days=int(s["baseline_days"])))
    series = daily_series(contribs, start, day, s)
    z = _z(series, len(series) - 1, 0, s)
    history_days = len(series) - 1
    items = {c.key for c in used}
    top = sorted(used, key=lambda c: (-c.weight * 0.5 ** ((day - c.day).days / float(s["half_life_days"])), c.key))
    return {"score": round(score, 3), "z": None if z is None else round(z, 3), "items": len(items),
            "history_days": history_days, "top": top[:3],
            "spike": z is not None and z >= float(s["z_spike"]) and len(items) >= int(s["min_items"])}


def by_ticker(contribs: list[Contribution]) -> dict[str, list[Contribution]]:
    out: dict[str, list[Contribution]] = {}
    for c in contribs:
        out.setdefault(c.ticker, []).append(c)
    return out


def coverage_start(contribs: list[Contribution]) -> date | None:
    return min((c.day for c in contribs), default=None)


def ranking(contribs: list[Contribution], day: date, s: dict) -> list[tuple[str, dict]]:
    start = coverage_start(contribs)
    if start is None:
        return []
    rows = [(ticker, pressure_on(items, day, start, s)) for ticker, items in by_ticker(contribs).items()]
    return sorted(((t, p) for t, p in rows if p["score"] > 0), key=lambda tp: (-tp[1]["score"], tp[0]))


def spike_days(contribs: list[Contribution], start: date, end: date, coverage: date, s: dict) -> list[tuple[date, dict]]:
    first = max(coverage, start - timedelta(days=int(s["baseline_days"])))
    series = daily_series(contribs, first, end, s)
    base = (start - first).days
    out, previous = [], False
    for i in range(base, len(series)):
        day = first + timedelta(days=i)
        z = _z(series, i, max(0, (coverage - first).days), s)
        spike = z is not None and z >= float(s["z_spike"])
        if spike:
            items = len({c.key for c in score_on(contribs, day, s)[1]})
            spike = items >= int(s["min_items"])
        if spike and not previous:
            out.append((day, pressure_on(contribs, day, coverage, s)))
        previous = spike
    return out


def close_time(day: date, calendar) -> datetime:
    session = calendar.session(day)
    if session:
        return session[1]
    return datetime.combine(day, datetime.min.time(), NY) + timedelta(hours=16)


def isfinite(value) -> bool:
    return value is not None and math.isfinite(value)
