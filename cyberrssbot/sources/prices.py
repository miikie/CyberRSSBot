from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta, timezone

from .. import prices
from ..http import FetchError
from ..market import NY
from .base import Source

log = logging.getLogger(__name__)

EXTRA_BENCHMARKS = ("CIBR", "HACK", "BUG", "SPY")
RETRY_MISSING_DAYS = 7


class PricesSource(Source):
    seed_on_first_run = False

    def __init__(self, app, cfg):
        super().__init__(app, cfg)
        self.years = float(cfg.get("history_years", 3))
        self.refresh_minute = int(cfg.get("refresh_minutes_after_close", 75))

    def next_interval(self) -> float:
        now = datetime.now(timezone.utc)
        open_at, close_at = self.app.market.next_session(now - timedelta(minutes=self.refresh_minute))
        target = close_at + timedelta(minutes=self.refresh_minute)
        return min(max(60.0, (target - now).total_seconds()), 6 * 3600)

    async def symbols(self) -> list[str]:
        wanted = set(EXTRA_BENCHMARKS) | set(self.app.companies.tracked) | set(self.app.finance.watch.benchmarks)
        wanted |= set(await self.app.store.event_tickers())
        return sorted(s for s in wanted if s)

    async def poll(self, seed: bool) -> int:
        app, store = self.app, self.app.store
        bounds = await store.price_bounds()
        last_close = prices.last_close_time(datetime.now(timezone.utc), app.market).astimezone(NY).date().isoformat()
        missing = await store.settings_get("prices.unavailable.")
        updated, failures = 0, []
        symbols = await self.symbols()
        for symbol in symbols:
            have = bounds.get(symbol)
            if have and have[1] >= last_close:
                continue
            if not have and symbol in missing and time.time() - float(missing[symbol]) < RETRY_MISSING_DAYS * 86400:
                continue
            try:
                if have:
                    gap = (datetime.fromisoformat(last_close) - datetime.fromisoformat(have[1])).days
                    rows, splits = await prices.fetch(app.http, symbol, days=gap + 7)
                else:
                    rows, splits = await prices.fetch(app.http, symbol, years=self.years)
            except FetchError as exc:
                if not have and (exc.status == 404 or "No data found" in str(exc) or "delisted" in str(exc)):
                    await store.setting_set("prices.unavailable." + symbol, str(int(time.time())))
                    log.info("no Yahoo prices for %s: %s", symbol, exc)
                else:
                    failures.append(f"{symbol}: {exc}")
                continue
            await store.prices_put(symbol, rows, prices.SOURCE)
            if splits:
                await store.splits_put(symbol, splits)
            await store.setting_delete("prices.unavailable." + symbol)
            updated += 1
        app.study.reset()
        if failures and len(failures) == len(symbols):
            raise FetchError("; ".join(failures)[:280])
        if failures:
            log.warning("prices partial failure: %s", "; ".join(failures)[:500])
        return updated

    async def flags(self) -> list[str]:
        today = datetime.now(timezone.utc).astimezone(NY).date()
        out = []
        for symbol in await self.symbols():
            rows = await self.app.store.prices_for(symbol)
            if rows:
                out += prices.quality_flags(symbol, rows, await self.app.store.splits_for(symbol), self.app.market,
                                            today)
        return out
