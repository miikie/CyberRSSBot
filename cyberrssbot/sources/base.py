from __future__ import annotations

import asyncio


class Source:
    seed_on_first_run = True

    def __init__(self, app, cfg: dict):
        self.app = app
        self.cfg = cfg
        self.id: str = cfg["id"]
        self.name: str = cfg.get("name") or self.id
        self.interval = float(cfg.get("interval") or app.cfg["poll"]["default_interval"])
        self.channel: str = cfg.get("channel", "news")
        self.wake = asyncio.Event()

    def next_interval(self) -> float:
        return self.interval

    async def poll(self, seed: bool) -> int:
        raise NotImplementedError
