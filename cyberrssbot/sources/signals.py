from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from .. import dossier, evidence, prices, render, signals
from ..market import NY
from .base import Source

log = logging.getLogger(__name__)
EVIDENCE_DEFAULTS = {"weekday": 6, "hour_utc": 14}
DOSSIER_SESSIONS_BEFORE = 2


class SignalsSource(Source):
    seed_on_first_run = True

    def __init__(self, app, cfg):
        super().__init__(app, cfg)
        self.after_close = int(cfg.get("minutes_after_close", 100))
        self.evidence = {**EVIDENCE_DEFAULTS, **((app.cfg.get("signals") or {}).get("evidence") or {})}

    def _next_report(self, now: datetime) -> datetime:
        target = now.replace(hour=int(self.evidence["hour_utc"]), minute=0, second=0, microsecond=0)
        target += timedelta(days=(int(self.evidence["weekday"]) - now.weekday()) % 7)
        return target if target > now else target + timedelta(days=7)

    def next_interval(self) -> float:
        now = datetime.now(timezone.utc)
        _, close_at = self.app.market.next_session(now - timedelta(minutes=self.after_close))
        target = min(close_at + timedelta(minutes=self.after_close), self._next_report(now) + timedelta(minutes=1))
        return min(max(60.0, (target - now).total_seconds()), 6 * 3600)

    async def poll(self, seed: bool) -> int:
        app, store = self.app, self.app.store
        now = datetime.now(timezone.utc)
        day = prices.last_close_time(now, app.market).astimezone(NY).date()
        count = 0
        key = f"fin:pressure:{day.isoformat()}"
        if seed or not await store.seen_any([key]):
            ranked = await app.fsignals.pressure(day, post=not seed)
            await store.mark_seen([key], self.id)
            count += sum(1 for _, p in ranked if p["spike"])
            s = signals.settings(app.cfg)
            week = "fin:pressure:week:" + "-".join(str(p) for p in day.isocalendar()[:2])
            if not seed and day.weekday() >= int(s["weekly_weekday"]) and not await store.seen_any([week]):
                await app.poster.send(self.channel, embed=render.pressure_table_embed(ranked, day, int(s["weekly_top"])))
                await store.mark_seen([week], self.id)
            elif seed:
                await store.mark_seen([week], self.id)
            await app.paperdesk.run(post=not seed)
            await self.pre_earnings(day, seed)
        await self.weekly_report(now, seed)
        return count

    async def pre_earnings(self, day, seed: bool) -> None:
        app, store = self.app, self.app.store
        rows = await store.earnings_between(day.isoformat(), (day + timedelta(days=10)).isoformat())
        for row in rows:
            if row.get("symbol") not in app.finance.watch.companies:
                continue
            earnings_day = datetime.fromisoformat(row["date"]).date()
            if dossier.sessions_before(earnings_day, DOSSIER_SESSIONS_BEFORE, app.market) != day:
                continue
            key = f"fin:dossier:{row['symbol']}:{row['date']}"
            if await store.seen_any([key]):
                continue
            await store.mark_seen([key], self.id)
            if seed:
                continue
            data = await dossier.build(app, row["symbol"])
            await app.poster.send("finance-earnings",
                                  embeds=render.dossier_embeds(data, app.poster.jump_url, compact=True))

    async def weekly_report(self, now: datetime, seed: bool) -> None:
        app, store = self.app, self.app.store
        last_due = self._next_report(now) - timedelta(days=7)
        if now < last_due or now - last_due > timedelta(days=1):
            return
        key = f"fin:evidence:{last_due.date().isoformat()}"
        if await store.seen_any([key]):
            return
        await store.mark_seen([key], self.id)
        if seed:
            return
        week, rows, paper_rows, health = await evidence.gather(app, now)
        text = evidence.compose(week, rows, paper_rows, health)
        for embed in render.report_embeds(text, "Weekly evidence report"):
            await app.poster.send(self.channel, embed=embed)
        await evidence.remember(app, rows, week)
