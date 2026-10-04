from __future__ import annotations

import bisect
from dataclasses import dataclass, field

PAPER_DEFAULTS = {"enabled": False, "starting_cash": 100000, "slippage_bps": 10, "rules": []}


@dataclass
class Rule:
    id: str
    event: str
    side: str = "short"
    min_confidence: float = 0.0
    entry: str = "next_open"
    sessions: int = 5
    stop_pct: float | None = None
    target_pct: float | None = None
    fixed_usd: float = 5000.0
    max_open: int = 5

    @classmethod
    def from_cfg(cls, raw: dict) -> "Rule":
        when, exit_, size = raw.get("when") or {}, raw.get("exit") or {}, raw.get("size") or {}
        side = str(raw.get("side", "short")).lower()
        if side not in ("long", "short"):
            raise ValueError(f"paper rule {raw.get('id')}: side must be long or short")
        return cls(id=str(raw["id"]), event=str(when["event"]), side=side,
                   min_confidence=float(when.get("min_confidence", 0) or 0), entry=str(raw.get("entry", "next_open")),
                   sessions=int(exit_.get("sessions", 5)), stop_pct=exit_.get("stop_pct"),
                   target_pct=exit_.get("target_pct"), fixed_usd=float(size.get("fixed_usd", 5000)),
                   max_open=int(raw.get("max_open", 5)))


@dataclass
class Trade:
    rule: str
    event_id: int
    ticker: str
    side: str
    entry_date: str
    entry_price: float
    shares: float
    exit_date: str | None = None
    exit_price: float | None = None
    exit_reason: str | None = None
    pnl: float | None = None
    ret: float | None = None

    @property
    def open(self) -> bool:
        return self.exit_date is None


@dataclass
class Result:
    trades: list[Trade] = field(default_factory=list)
    skipped: list[tuple[int, str]] = field(default_factory=list)
    daily: list[tuple[str, float, float]] = field(default_factory=list)


def entry_index(ev: dict, calendar: list[str]) -> int:
    idx = bisect.bisect_left(calendar, ev["effective_session"])
    if ev["session_timing"] == "intraday":
        idx += 1
    return idx


def fill(price: float, side: str, opening: bool, bps: float) -> float:
    buying = (side == "long") == opening
    return price * (1 + bps / 10000) if buying else price * (1 - bps / 10000)


def _exit_check(t: Trade, rule: Rule, bar: dict, held: int) -> tuple[float | None, str | None]:
    long = t.side == "long"
    stop = t.entry_price * (1 - rule.stop_pct / 100 if long else 1 + rule.stop_pct / 100) if rule.stop_pct else None
    target = t.entry_price * (1 + rule.target_pct / 100 if long else 1 - rule.target_pct / 100)         if rule.target_pct else None
    if stop is not None and (bar["low"] <= stop if long else bar["high"] >= stop):
        return stop, "stop"
    if target is not None and (bar["high"] >= target if long else bar["low"] <= target):
        return target, "target"
    if held >= rule.sessions:
        return bar["close"], "time"
    return None, None


def _close(t: Trade, day: str, raw_price: float, reason: str, bps: float) -> float:
    price = fill(raw_price, t.side, False, bps)
    sign = 1 if t.side == "long" else -1
    t.exit_date, t.exit_price, t.exit_reason = day, round(price, 4), reason
    t.pnl = round(sign * (price - t.entry_price) * t.shares, 2)
    t.ret = round(sign * (price / t.entry_price - 1), 6)
    return t.entry_price * t.shares + t.pnl if t.side == "long" else t.pnl


def simulate(rule: Rule, events: list[dict], bars: dict[str, dict[str, dict]], calendar: list[str], *,
             starting_cash: float, slippage_bps: float, start: str | None = None, end: str | None = None) -> Result:
    result = Result()
    eligible = sorted((e for e in events if e["type"] == rule.event and e["ticker"]
                       and (e["confidence"] or 0) >= rule.min_confidence), key=lambda e: (e["effective_session"], e["id"]))
    pending: dict[int, list[dict]] = {}
    for ev in eligible:
        idx = entry_index(ev, calendar)
        if idx >= len(calendar) or (start and calendar[idx] < start):
            continue
        pending.setdefault(idx, []).append(ev)
    cash, open_trades, entered_at = float(starting_cash), [], {}
    last_close: dict[str, float] = {}
    for i, day in enumerate(calendar):
        if end and day > end:
            break
        for t in list(open_trades):
            bar = bars.get(t.ticker, {}).get(day)
            if not bar:
                continue
            price, reason = _exit_check(t, rule, bar, i - entered_at[id(t)] + 1)
            if price is not None:
                cash += _close(t, day, price, reason, slippage_bps)
                open_trades.remove(t)
        for ev in pending.get(i, []):
            bar = bars.get(ev["ticker"], {}).get(day)
            if not bar or not bar.get("open"):
                result.skipped.append((ev["id"], "no price"))
                continue
            if len(open_trades) >= rule.max_open:
                result.skipped.append((ev["id"], "max_open"))
                continue
            if rule.side == "long" and cash < rule.fixed_usd:
                result.skipped.append((ev["id"], "cash"))
                continue
            price = fill(bar["open"], rule.side, True, slippage_bps)
            trade = Trade(rule.id, ev["id"], ev["ticker"], rule.side, day, round(price, 4),
                          round(rule.fixed_usd / price, 6))
            if rule.side == "long":
                cash -= trade.entry_price * trade.shares
            entered_at[id(trade)] = i
            result.trades.append(trade)
            exit_price, reason = _exit_check(trade, rule, bar, 1)
            if exit_price is not None:
                cash += _close(trade, day, exit_price, reason, slippage_bps)
            else:
                open_trades.append(trade)
        for t in open_trades:
            bar = bars.get(t.ticker, {}).get(day)
            if bar and bar.get("close"):
                last_close[t.ticker] = bar["close"]
        marked = 0.0
        for t in open_trades:
            close = last_close.get(t.ticker, t.entry_price)
            marked += close * t.shares if t.side == "long" else (t.entry_price - close) * t.shares
        if result.trades:
            result.daily.append((day, round(cash + marked, 2), round(cash, 2)))
    return result


def stats(result: Result, bench: dict[str, dict[str, float]] | None = None, calendar: list[str] | None = None,
          bench_for=None) -> dict:
    closed = [t for t in result.trades if not t.open]
    out = {"trades": len(result.trades), "closed": len(closed), "open": len(result.trades) - len(closed),
           "skipped": len(result.skipped)}
    if closed:
        out.update(win_rate=sum(1 for t in closed if t.pnl > 0) / len(closed),
                   avg_return=sum(t.ret for t in closed) / len(closed),
                   total_pnl=round(sum(t.pnl for t in closed), 2))
    peak, drawdown = None, 0.0
    for _, equity, _ in result.daily:
        peak = equity if peak is None else max(peak, equity)
        drawdown = min(drawdown, equity / peak - 1)
    out["max_drawdown"] = round(drawdown, 6)
    if bench and calendar and closed:
        returns = []
        for t in closed:
            series = bench.get(bench_for(t.ticker) if bench_for else "SPY") or bench.get("SPY") or {}
            days = calendar[calendar.index(t.entry_date):calendar.index(t.exit_date) + 1]
            growth = 1.0
            for d in days:
                growth *= 1 + series.get(d, 0.0)
            returns.append(growth - 1)
        out["benchmark_avg_return"] = sum(returns) / len(returns)
        out["benchmark_total_pnl"] = round(sum(r * t.entry_price * t.shares for r, t in zip(returns, closed)), 2)
    return out
