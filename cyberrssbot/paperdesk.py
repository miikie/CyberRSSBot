from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict
from datetime import datetime, timezone

from . import paper, render, study
from .market import NY

log = logging.getLogger(__name__)


class PaperDesk:
    def __init__(self, app):
        self.app = app
        cfg = {**paper.PAPER_DEFAULTS, **(app.cfg.get("paper") or {})}
        self.enabled = bool(cfg["enabled"])
        self.starting_cash = float(cfg["starting_cash"])
        self.slippage_bps = float(cfg["slippage_bps"])
        self.rules = [paper.Rule.from_cfg(r) for r in cfg.get("rules") or []]
        self.channel = "finance-signals"

    def rule(self, rule_id: str) -> paper.Rule | None:
        return next((r for r in self.rules if r.id == rule_id), None)

    async def inputs(self, rule: paper.Rule) -> tuple[list[dict], dict, list[str], dict]:
        store = self.app.store
        events = await store.events_query(type_=rule.event)
        bars = {}
        for ticker in sorted({e["ticker"] for e in events if e["ticker"]}):
            bars[ticker] = {r["date"]: r for r in await store.prices_for(ticker) if r.get("open") and r.get("close")}
        calendar = [r["date"] for r in await store.prices_for("SPY")]
        bench = {s: study.daily_returns(await store.prices_for(s)) for s in ("SPY", "CIBR")}
        return events, bars, calendar, bench

    async def backtest(self, rule: paper.Rule) -> dict:
        events, bars, calendar, bench = await self.inputs(rule)
        result = paper.simulate(rule, events, bars, calendar, starting_cash=self.starting_cash,
                                slippage_bps=self.slippage_bps)
        return {"rule": rule, "result": result,
                "stats": paper.stats(result, bench, calendar, self.app.companies.benchmark),
                "first": calendar[0] if calendar else None, "last": calendar[-1] if calendar else None}

    async def run(self, *, post: bool) -> dict:
        if not self.enabled:
            return {}
        store, out = self.app.store, {}
        today = datetime.now(timezone.utc).astimezone(NY).date().isoformat()
        for rule in self.rules:
            created = await store.paper_rule_start(rule.id, json.dumps(asdict(rule), sort_keys=True), today)
            events, bars, calendar, _ = await self.inputs(rule)
            result = paper.simulate(rule, events, bars, calendar, starting_cash=self.starting_cash,
                                    slippage_bps=self.slippage_bps, start=created)
            posted = await store.paper_trades_replace(rule.id, result.trades, result.daily)
            out[rule.id] = len(result.trades)
            if not post:
                await store.paper_mark_posted(rule.id)
                continue
            for trade, kind in posted:
                ev = await store.event_get(trade["event_id"])
                jump = None
                if ev:
                    ref = ev["source_refs"].get("message") or ev["source_refs"].get("post")
                    jump = self.app.poster.jump_url(*ref) if ref else ev["source_refs"].get("filing")
                msg = await self.app.poster.send(self.channel, content=render.paper_line(trade, kind, ev, jump))
                if msg:
                    await store.paper_set_posted(rule.id, trade["event_id"], kind)
        return out

    async def summary(self) -> list[dict]:
        rows = []
        for rule in self.rules:
            trades = [paper.Trade(**{k: t[k] for k in paper.Trade.__dataclass_fields__})
                      for t in await self.app.store.paper_trades(rule.id)]
            daily = await self.app.store.paper_daily(rule.id)
            _, _, calendar, bench = await self.inputs(rule)
            result = paper.Result(trades=trades, daily=daily)
            rows.append({"rule": rule.id, **paper.stats(result, bench, calendar, self.app.companies.benchmark)})
        return rows
