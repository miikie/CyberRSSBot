from __future__ import annotations

import json
import math
from datetime import datetime, timedelta

from .events import EVENT_TYPES

Q = 0.10
MIN_LABEL_N = 30
SETTINGS_KEY = "evidence.last"


def _betacf(a: float, b: float, x: float) -> float:
    tiny, qab, qap, qam = 1e-300, a + b, a + 1, a - 1
    c, d = 1.0, 1 - qab * x / qap
    d = 1 / (d if abs(d) > tiny else tiny)
    h = d
    for m in range(1, 300):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1 + aa * d
        d = 1 / (d if abs(d) > tiny else tiny)
        c = 1 + aa / c if abs(1 + aa / c) > tiny else tiny
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1 + aa * d
        d = 1 / (d if abs(d) > tiny else tiny)
        c = 1 + aa / c if abs(1 + aa / c) > tiny else tiny
        delta = d * c
        h *= delta
        if abs(delta - 1) < 1e-14:
            break
    return h


def betainc(a: float, b: float, x: float) -> float:
    if x <= 0:
        return 0.0
    if x >= 1:
        return 1.0
    front = math.exp(math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b) + a * math.log(x) + b * math.log(1 - x))
    if x < (a + 1) / (a + b + 2):
        return front * _betacf(a, b, x) / a
    return 1 - front * _betacf(b, a, 1 - x) / b


def t_pvalue(t: float, df: int) -> float:
    if df <= 0:
        return 1.0
    return betainc(df / 2, 0.5, df / (df + t * t))


def benjamini_hochberg(pvalues: dict[str, float], q: float = Q) -> set[str]:
    ranked = sorted(pvalues.items(), key=lambda kv: (kv[1], kv[0]))
    m = len(ranked)
    cutoff = 0
    for k, (_, p) in enumerate(ranked, 1):
        if p <= k / m * q:
            cutoff = k
    return {name for name, _ in ranked[:cutoff]}


def label(n: int, passed: bool) -> str:
    if n < MIN_LABEL_N:
        return "collecting"
    return "promising" if passed else "noise"


def _pct(v) -> str:
    return "—" if v is None else f"{v * 100:+.2f}%"


def build_rows(summaries: dict[str, dict], new_counts: dict[str, int], last: dict[str, dict]) -> list[dict]:
    rows, pvalues = [], {}
    for type_ in sorted(summaries):
        s = summaries[type_]
        if not s["total"]:
            continue
        p = t_pvalue(s["t"], s["n"] - 1) if s.get("t") is not None and s["n"] > 1 else None
        if p is not None:
            pvalues[type_] = p
        prev = last.get(type_) or {}
        change = None if prev.get("mean") is None or s.get("mean") is None else s["mean"] - prev["mean"]
        rows.append({"type": type_, "new": new_counts.get(type_, 0), "total": s["total"], "n": s["n"],
                     "mean": s.get("mean"), "median": s.get("median"), "ci": s.get("ci"),
                     "hit": s.get("share_negative"), "p": p, "change": change})
    passed = benjamini_hochberg(pvalues)
    for row in rows:
        row["label"] = label(row["n"], row["type"] in passed)
    return rows


def compose(week: str, rows: list[dict], paper: list[dict], health: dict) -> str:
    lines = [f"Weekly evidence report · {week}",
             "CAR[0,+5]: 5-session market-adjusted abnormal return after each event type (events filed during the "
             "session excluded). Observed historically; not a forecast.", ""]
    order = {"promising": 0, "noise": 1, "collecting": 2}
    for row in sorted(rows, key=lambda r: (order[r["label"]], -r["n"], r["type"])):
        ci = f"{_pct(row['ci'][0])} to {_pct(row['ci'][1])}" if row["ci"] else "—"
        change = "first week" if row["change"] is None else f"{row['change'] * 100:+.2f} pts vs last week"
        p = "—" if row["p"] is None else f"{row['p']:.3f}"
        lines.append(f"{row['type']} [{row['label']}]")
        lines.append(f"  events {row['new']} new / {row['total']} total · studied n={row['n']} · mean {_pct(row['mean'])}"
                     f" · median {_pct(row['median'])} · 95% CI {ci}")
        hit = "—" if row["hit"] is None else f"{row['hit']:.0%}"
        lines.append(f"  share negative {hit} · p={p} · {change}")
    lines += ["", f"Labels: promising = n ≥ {MIN_LABEL_N} and passes Benjamini-Hochberg at q = {Q:.2f} across all "
              f"types tested this week ({sum(1 for r in rows if r['p'] is not None)}); noise = n ≥ {MIN_LABEL_N} and "
              "fails; collecting = fewer events.", ""]
    if paper:
        lines.append("Paper trading (simulated, no real orders; short borrow costs ignored):")
        for r in paper:
            if not r.get("closed"):
                lines.append(f"  {r['rule']}: {r['trades']} trades, none closed yet")
                continue
            lines.append(f"  {r['rule']}: {r['closed']} closed, win rate {r['win_rate']:.0%}, average {_pct(r['avg_return'])},"
                         f" P&L ${r['total_pnl']:,.0f} vs benchmark {_pct(r.get('benchmark_avg_return'))} per trade,"
                         f" max drawdown {_pct(r['max_drawdown'])}")
    else:
        lines.append("Paper trading: off.")
    lines += ["", f"Data health: {health['price_flags']} price-quality flags, {len(health['failed_sources'])} failing "
              f"source(s){': ' + ', '.join(health['failed_sources']) if health['failed_sources'] else ''}, "
              f"latest price {health['latest_price'] or 'none'}{' (stale)' if health.get('stale') else ''}."]
    return "\n".join(lines)


async def gather(app, now: datetime) -> tuple[str, list[dict], list[dict], dict]:
    store = app.store
    week_start = (now - timedelta(days=7)).date().isoformat()
    counts = await store.event_counts()
    summaries, new_counts = {}, {}
    for type_ in EVENT_TYPES:
        total = counts.get(type_, 0)
        if not total:
            continue
        result = await app.study.aggregate(type_, "car_0_5")
        s = result["main"]["summary"]
        summaries[type_] = {"total": total, "n": s.n, "mean": s.mean, "median": s.median, "ci": s.ci,
                            "share_negative": s.share_negative, "t": s.t_stat}
        new_counts[type_] = sum(1 for e in await store.events_query(type_=type_, since=week_start))
    last = json.loads(await store.setting_get(SETTINGS_KEY) or "{}")
    rows = build_rows(summaries, new_counts, last.get("rows") or {})
    paper_rows = await app.paperdesk.summary() if app.paperdesk.enabled else []
    prices_src = next((s for s in app.sources if s.cfg.get("type") == "prices"), None)
    flags = await prices_src.flags() if prices_src else []
    states = {r["id"]: r for r in await store.all_sources()}
    bounds = await store.price_bounds()
    latest = max((b[1] for b in bounds.values()), default=None)
    stale = bool(latest and (now.date() - datetime.fromisoformat(latest).date()).days > 5)
    health = {"price_flags": len(flags), "failed_sources": sorted(s for s, r in states.items() if (r.get("fails") or 0) > 0),
              "latest_price": latest, "stale": stale}
    return week_start, rows, paper_rows, health


async def remember(app, rows: list[dict], week: str) -> None:
    await app.store.setting_set(SETTINGS_KEY, json.dumps(
        {"week": week, "rows": {r["type"]: {"mean": r["mean"], "n": r["n"]} for r in rows}}, sort_keys=True))
