from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .. import prices, render, signals
from ..market import NY
from .base import Source


class SignalsSource(Source):
    seed_on_first_run = True

    def __init__(self, app, cfg):
        super().__init__(app, cfg)
        self.after_close = int(cfg.get("minutes_after_close", 100))

    def next_interval(self) -> float:
        now = datetime.now(timezone.utc)
        _, close_at = self.app.market.next_session(now - timedelta(minutes=self.after_close))
        target = close_at + timedelta(minutes=self.after_close)
        return min(max(60.0, (target - now).total_seconds()), 6 * 3600)

    async def poll(self, seed: bool) -> int:
        app = self.app
        day = prices.last_close_time(datetime.now(timezone.utc), app.market).astimezone(NY).date()
        key = f"fin:pressure:{day.isoformat()}"
        if await app.store.seen_any([key]) and not seed:
            return 0
        ranked = await app.fsignals.pressure(day, post=not seed)
        await app.store.mark_seen([key], self.id)
        s = signals.settings(app.cfg)
        week = "fin:pressure:week:" + "-".join(str(p) for p in day.isocalendar()[:2])
        if not seed and day.weekday() >= int(s["weekly_weekday"]) and not await app.store.seen_any([week]):
            await app.poster.send(self.channel, embed=render.pressure_table_embed(ranked, day, int(s["weekly_top"])))
            await app.store.mark_seen([week], self.id)
        elif seed:
            await app.store.mark_seen([week], self.id)
        return sum(1 for _, p in ranked if p["spike"])
