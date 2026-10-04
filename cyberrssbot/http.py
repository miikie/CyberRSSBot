from __future__ import annotations

import asyncio
import random
import ssl
import time
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from urllib.parse import urlencode, urlsplit

import aiohttp
import certifi

DEFAULT_UA = "Mozilla/5.0 (compatible; CyberRSSBot/1.0; +security news aggregator)"
FEED_ACCEPT = "application/rss+xml, application/atom+xml, application/xml;q=0.9, text/xml;q=0.9, */*;q=0.8"


class FetchError(Exception):
    def __init__(self, message: str, status: int | None = None, retry_after: float | None = None):
        super().__init__(message)
        self.status = status
        self.retry_after = retry_after


@dataclass
class Fetched:
    body: bytes
    cache_key: str
    etag: str | None = None
    last_modified: str | None = None


def _retry_after(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    try:
        return max(0.0, parsedate_to_datetime(value).timestamp() - time.time())
    except (TypeError, ValueError):
        return None


class HostLimiter:
    def __init__(self, default_interval: float, overrides: dict[str, float]):
        self.default = float(default_interval)
        self.overrides = {k.lower(): float(v) for k, v in (overrides or {}).items()}
        self._locks: dict[str, asyncio.Lock] = {}
        self._last: dict[str, float] = {}

    async def wait(self, host: str) -> None:
        lock = self._locks.setdefault(host, asyncio.Lock())
        async with lock:
            gap = self.overrides.get(host, self.default) - (time.monotonic() - self._last.get(host, 0.0))
            if gap > 0:
                await asyncio.sleep(gap)
            self._last[host] = time.monotonic()


class Http:
    def __init__(self, store, net_cfg: dict, host_overrides: dict[str, float]):
        self.store = store
        self.limiter = HostLimiter(net_cfg.get("host_min_interval_default", 2.0), host_overrides)
        self.timeout = aiohttp.ClientTimeout(total=float(net_cfg.get("timeout", 45)))
        self.user_agent = net_cfg.get("user_agent") or DEFAULT_UA
        self.session: aiohttp.ClientSession | None = None

    async def start(self) -> None:
        connector = aiohttp.TCPConnector(ssl=ssl.create_default_context(cafile=certifi.where()))
        self.session = aiohttp.ClientSession(timeout=self.timeout, connector=connector,
                                             headers={"User-Agent": self.user_agent})

    async def close(self) -> None:
        if self.session:
            await self.session.close()

    async def get(self, url: str, *, params: dict | None = None, headers: dict | None = None,
                  conditional: bool = True, retries: int = 2, timeout: float | None = None) -> Fetched | None:
        host = (urlsplit(url).hostname or "").lower()
        cache_key = url + ("?" + urlencode(sorted(params.items())) if params else "")
        hdrs = {"Accept": FEED_ACCEPT, **(headers or {})}
        if conditional:
            etag, last_mod = await self.store.http_cache_get(cache_key)
            if etag:
                hdrs["If-None-Match"] = etag
            if last_mod:
                hdrs["If-Modified-Since"] = last_mod

        extra = {"timeout": aiohttp.ClientTimeout(total=timeout)} if timeout else {}
        for attempt in range(retries + 1):
            await self.limiter.wait(host)
            try:
                async with self.session.get(url, params=params, headers=hdrs, allow_redirects=True,
                                            **extra) as resp:
                    status = resp.status
                    if status == 304:
                        return None
                    if status < 400:
                        body = await resp.read()
                        return Fetched(body, cache_key, resp.headers.get("ETag"), resp.headers.get("Last-Modified"))
                    retry_after = _retry_after(resp.headers.get("Retry-After"))
            except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                if attempt == retries:
                    raise FetchError(f"{type(exc).__name__}: {exc}") from exc
                await asyncio.sleep(2 ** attempt * 2 + random.random())
                continue

            retryable = status == 429 or status >= 500
            if not retryable or attempt == retries or (retry_after and retry_after > 60):
                raise FetchError(f"HTTP {status}", status=status, retry_after=retry_after)
            await asyncio.sleep(retry_after if retry_after is not None else 2 ** attempt * 3 + random.random())
        raise FetchError("unreachable")

    async def commit(self, fetched: Fetched | None) -> None:
        if fetched and (fetched.etag or fetched.last_modified):
            await self.store.http_cache_set(fetched.cache_key, fetched.etag, fetched.last_modified)
