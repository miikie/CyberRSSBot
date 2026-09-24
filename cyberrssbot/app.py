from __future__ import annotations

import asyncio
import json
import logging
import os
import random
import tempfile
import time

from . import render
from .engine import StoryEngine, VulnEngine
from .finance import FinanceEngine
from .http import FetchError, Http
from .market import MarketCalendar
from .sources import build_sources
from .store import Store

log = logging.getLogger("cyberrssbot")

FINNHUB_URL = "https://finnhub.io/api/v1"


class NullPoster:
    async def send(self, *args, **kwargs):
        return None

    async def edit(self, *args, **kwargs):
        return "ok"

    def jump_url(self, *args):
        return None


class App:
    def __init__(self, cfg: dict, *, db_path: str | None = None):
        self.cfg = cfg
        self.store = Store(db_path or cfg["database"])
        overrides = dict(cfg["network"].get("host_min_interval") or {})
        if cfg["secrets"]["nvd_api_key"]:
            overrides["services.nvd.nist.gov"] = min(float(overrides.get("services.nvd.nist.gov", 0.7)), 0.7)
        self.http = Http(self.store, cfg["network"], overrides)
        self.poster = NullPoster()
        self.vulns = VulnEngine(self)
        self.stories = StoryEngine(self)
        self.market = MarketCalendar()
        self.finance = FinanceEngine(self)
        self.sources = build_sources(self)
        self.tasks: list[asyncio.Task] = []
        self._holidays_day = None

    async def start(self) -> None:
        await self.store.open()
        await self.http.start()
        await self.stories.load()
        await self.finance.load()

    async def finnhub(self, path: str, **params):
        key = self.cfg["secrets"].get("finnhub_api_key")
        if not key:
            raise FetchError("FINNHUB_API_KEY is not set")
        fetched = await self.http.get(FINNHUB_URL + path, params=params, conditional=False,
                                      headers={"X-Finnhub-Token": key, "Accept": "application/json"})
        return json.loads(fetched.body)

    async def refresh_holidays(self) -> None:
        today = time.strftime("%Y-%m-%d")
        if self._holidays_day == today or not self.cfg["secrets"].get("finnhub_api_key"):
            return
        try:
            data = await self.finnhub("/stock/market-holiday", exchange="US")
            self.market.load_finnhub((data or {}).get("data") or [])
            self._holidays_day = today
        except (FetchError, ValueError) as exc:
            log.warning("market holiday refresh failed, using built-in NYSE rules: %s", exc)

    async def close(self) -> None:
        for task in self.tasks:
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
        await self.http.close()
        await self.store.close()

    def launch_background(self) -> None:
        for i, src in enumerate(self.sources):
            self.tasks.append(asyncio.create_task(self._run_source(src, i * 3.0), name=f"source:{src.id}"))
        self.tasks.append(asyncio.create_task(self._flush_loop(), name="flush"))

    async def _run_source(self, src, initial_delay: float) -> None:
        await asyncio.sleep(initial_delay)
        while True:
            try:
                wait = await self.poll_once(src)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("scheduler error in %s", src.id)
                wait = src.interval
            try:
                await asyncio.wait_for(src.wake.wait(), timeout=wait)
            except asyncio.TimeoutError:
                pass
            src.wake.clear()

    async def poll_once(self, src, *, force_seed: bool = False) -> float:
        state = await self.store.source_get(src.id)
        seed = force_seed or (src.seed_on_first_run and not state.get("seeded"))
        prev_fails = state.get("fails") or 0
        try:
            count = await src.poll(seed)
        except FetchError as exc:
            error, retry_after = str(exc), exc.retry_after
        except Exception as exc:
            log.exception("source %s crashed", src.id)
            error, retry_after = f"{type(exc).__name__}: {exc}", None
        else:
            await self.store.source_update(src.id, last_ok=int(time.time()), fails=0, seeded=1,
                                           items=(state.get("items") or 0) + count, last_err=None)
            if seed:
                log.info("seeded %-24s %4d items", src.id, count)
            elif count:
                log.info("polled %-24s %4d new", src.id, count)
            if prev_fails >= 3:
                await self._notify(f"✅ `{src.id}` recovered after {prev_fails} failures")
            return src.next_interval() * random.uniform(0.9, 1.15)

        fails = prev_fails + 1
        await self.store.source_update(src.id, fails=fails, last_err=error[:300], last_err_ts=int(time.time()))
        log.warning("source %s failed (%d in a row): %s", src.id, fails, error)
        if fails == 3:
            await self._notify(f"⚠️ `{src.id}` has failed 3 times in a row: {error[:200]}")
        wait = min(src.interval * 2 ** min(fails - 1, 5), 6 * 3600)
        return max(wait, retry_after or 0)

    async def _notify(self, text: str) -> None:
        await self.poster.send("log", content=text, fallback=False)

    async def _flush_loop(self) -> None:
        last_prune = 0.0
        while True:
            await asyncio.sleep(45)
            try:
                for row in await self.store.vulns_dirty():
                    result = await self.poster.edit(row["channel_id"], row["message_id"], render.vuln_embed(row["data"]))
                    if result == "gone":
                        await self.store.vuln_set_post(row["vid"], 1, None, None)
                    elif result == "ok":
                        await self.store.vuln_mark_dirty(row["vid"], 0)
                for row in await self.store.fin_dirty():
                    result = await self.poster.edit(row["channel_id"], row["message_id"],
                                                    render.finance_item_embed(row["data"]))
                    if result == "gone":
                        await self.store.fin_update(row["id"], dirty=0, clear_message=True)
                    elif result == "ok":
                        await self.store.fin_update(row["id"], dirty=0)
                for row in await self.store.stories_dirty():
                    result = await self.poster.edit(row["channel_id"], row["message_id"], render.story_embed(row["data"]))
                    if result == "gone":
                        await self.store.story_update(row["id"], dirty=0, clear_message=True)
                    elif result == "ok":
                        await self.store.story_update(row["id"], dirty=0)
                if time.time() - last_prune > 86400:
                    await self.store.prune()
                    last_prune = time.time()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("flush loop error")


async def run_check(cfg: dict) -> int:
    with tempfile.TemporaryDirectory() as tmp:
        app = App(cfg, db_path=os.path.join(tmp, "check.db"))
        await app.start()

        async def one(src):
            started = time.monotonic()
            try:
                count = await src.poll(True)
                return src.id, "OK  ", f"{count} items", time.monotonic() - started
            except Exception as exc:
                return src.id, "FAIL", f"{type(exc).__name__}: {exc}"[:110], time.monotonic() - started

        try:
            results = await asyncio.gather(*(one(s) for s in app.sources))
        finally:
            await app.close()

    width = max((len(r[0]) for r in results), default=10)
    for sid, status, detail, secs in results:
        print(f"{status} {sid:<{width}}  {secs:5.1f}s  {detail}")
    failed = sum(1 for r in results if r[1].startswith("FAIL"))
    print(f"\n{len(results) - failed}/{len(results)} sources healthy")
    return 1 if failed else 0
