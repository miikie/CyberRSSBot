from __future__ import annotations

import difflib
import json
import logging
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

SEC_TICKERS_URL = "https://www.sec.gov/files/company_tickers_exchange.json"
SUFFIXES = frozenset("""inc incorporated corp corporation llc ltd limited plc holdings holding group co company the""".split())
FUZZY_CUTOFF = 0.9
FUZZY_CONFIDENCE = 0.8
_PUNCT_RE = re.compile(r"[^0-9a-z]+")
_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9&'.\-]*")
_DOMAIN_RE = re.compile(r"^(?:https?://)?(?:www\.)?([a-z0-9-]+)\.[a-z.]{2,}(?:/.*)?$", re.IGNORECASE)


def normalize(name: str | None) -> str:
    text = (name or "").casefold().replace("&", " and ")
    tokens = [t for t in _PUNCT_RE.sub(" ", text).split() if t not in SUFFIXES]
    return " ".join(tokens)


@dataclass(frozen=True)
class Company:
    ticker: str
    cik: int | None
    name: str
    exchange: str | None
    confidence: float
    method: str


class Companies:
    def __init__(self, cfg: dict, cache_dir: str, extras_dir: Path):
        self.cfg = cfg
        self.cache_path = Path(cache_dir) / "sec_tickers.json"
        self.refresh_seconds = float((cfg.get("kb") or {}).get("refresh_days", 7)) * 86400
        self.extras_dir = Path(extras_dir)
        self.by_cik: dict[int, tuple[str, str, str | None]] = {}
        self.by_ticker: dict[str, tuple[int, str, str | None]] = {}
        self.by_norm: dict[str, set[int]] = {}
        self.aliases: dict[str, str] = {}
        self.exposure: dict[str, str] = {}
        self.exposure_compact: dict[str, str] = {}
        self.private: set[str] = set()
        self.tracked: dict[str, str] = {}
        self.blocklist: frozenset[str] = frozenset()
        self.status = "not loaded"

    def load(self) -> None:
        path = self.extras_dir / "company_blocklist.txt"
        self.blocklist = frozenset(normalize(w) for w in path.read_text(encoding="utf-8").split("\n")
                                   if w.strip() and not w.startswith("#")) if path.is_file() else frozenset()
        by_cik, by_ticker, by_norm = {}, {}, {}
        try:
            cached = json.loads(self.cache_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            cached = {"rows": []}
        for cik, name, ticker, exchange in cached.get("rows") or []:
            if not ticker:
                continue
            cik = int(cik)
            by_ticker.setdefault(ticker.upper(), (cik, name, exchange))
            if cik not in by_cik:
                by_cik[cik] = (ticker.upper(), name, exchange)
                by_norm.setdefault(normalize(name), set()).add(cik)
        self.by_cik, self.by_ticker, self.by_norm = by_cik, by_ticker, by_norm

        aliases, tracked = {}, {}
        for ticker, info in ((self.cfg.get("finance") or {}).get("companies") or {}).items():
            tracked[ticker.upper()] = info.get("name") or ticker
            for alias in (info.get("name"), *(info.get("aliases") or [])):
                if alias:
                    aliases[normalize(alias)] = ticker.upper()
        exposure_cfg = self.cfg.get("exposure") or {}
        exposure = {normalize(k): str(v).upper() for k, v in (exposure_cfg.get("vendors") or {}).items()}
        for norm, ticker in aliases.items():
            exposure.setdefault(norm, ticker)
        for vendor, ticker in exposure.items():
            tracked.setdefault(ticker, vendor)
        self.aliases, self.exposure, self.tracked = aliases, exposure, tracked
        self.exposure_compact = {k.replace(" ", ""): v for k, v in exposure.items()}
        self.private = {normalize(p) for p in exposure_cfg.get("private") or []}
        missing = sorted({t for t in exposure.values() if by_ticker and t not in by_ticker})
        if missing:
            log.warning("exposure tickers not in the SEC ticker list (delisted or renamed?): %s", ", ".join(missing))
        self.status = f"{len(by_cik)} listed companies, {len(exposure)} exposure vendors"

    def stale(self) -> bool:
        try:
            cached = json.loads(self.cache_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return True
        return time.time() - float(cached.get("fetched") or 0) > self.refresh_seconds

    async def refresh(self, http, user_agent: str | None, *, force: bool = False) -> str:
        if not force and not self.stale():
            self.load()
            return "fresh"
        if not user_agent:
            self.load()
            return "failed (no SEC user agent); " + ("using the cached copy" if self.cache_path.exists() else
                                                     "no cached copy yet")
        try:
            fetched = await http.get(SEC_TICKERS_URL, headers={"User-Agent": user_agent, "Accept": "application/json"},
                                     conditional=False)
            data = json.loads(fetched.body)
            rows = data["data"]
            if not rows:
                raise ValueError("empty ticker file")
        except Exception as exc:
            self.load()
            have = "using the cached copy" if self.cache_path.exists() else "no cached copy yet"
            log.warning("SEC ticker file refresh failed: %s; %s", exc, have)
            return f"failed ({type(exc).__name__}: {exc}); {have}"
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.cache_path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"fetched": int(time.time()), "fields": data.get("fields"), "rows": rows}),
                       encoding="utf-8")
        os.replace(tmp, self.cache_path)
        self.load()
        return f"{len(rows)} tickers"

    def by_cik_company(self, cik: int | None) -> Company | None:
        found = self.by_cik.get(int(cik)) if cik else None
        return Company(found[0], int(cik), found[1], found[2], 1.0, "cik") if found else None

    def by_ticker_company(self, ticker: str, confidence: float = 1.0, method: str = "ticker") -> Company | None:
        found = self.by_ticker.get((ticker or "").upper())
        if found:
            return Company(ticker.upper(), found[0], found[1], found[2], confidence, method)
        if ticker and ticker.upper() in self.tracked:
            return Company(ticker.upper(), None, self.tracked[ticker.upper()], None, confidence, method)
        return None

    def resolve(self, name: str | None) -> Company | None:
        raw = (name or "").strip()
        domain = _DOMAIN_RE.match(raw.split()[0]) if raw else None
        norm = normalize(domain.group(1).replace("-", " ") if domain else raw)
        if not norm or norm in self.private:
            return None
        if norm in self.aliases:
            return self.by_ticker_company(self.aliases[norm], 1.0, "watchlist")
        ciks = self.by_norm.get(norm)
        if ciks:
            if len(ciks) != 1:
                return None
            cik = next(iter(ciks))
            return Company(self.by_cik[cik][0], cik, self.by_cik[cik][1], self.by_cik[cik][2], 1.0, "exact")
        if domain or not self._fuzzy_allowed(norm):
            return None
        close = difflib.get_close_matches(norm, list(self.by_norm), n=2, cutoff=FUZZY_CUTOFF)
        if len(close) != 1 or len(self.by_norm[close[0]]) != 1:
            return None
        cik = next(iter(self.by_norm[close[0]]))
        return Company(self.by_cik[cik][0], cik, self.by_cik[cik][1], self.by_cik[cik][2], FUZZY_CONFIDENCE, "fuzzy")

    def _fuzzy_allowed(self, norm: str) -> bool:
        tokens = norm.split()
        if norm in self.blocklist or all(t in self.blocklist for t in tokens):
            return False
        return len(norm) >= 6 and (len(tokens) >= 2 or len(norm) >= 8)

    def find_in_text(self, text: str) -> list[Company]:
        words = _TOKEN_RE.findall(text or "")
        found: dict[str, Company] = {}
        single = {**{n: t for n, t in self.exposure.items() if " " not in n}, **{n: t for n, t in self.aliases.items()}}
        lowered = [normalize(w) for w in words]
        for size in range(6, 0, -1):
            for i in range(0, len(words) - size + 1):
                span = words[i:i + size]
                if not all(w[0].isupper() or w[0].isdigit() for w in span):
                    continue
                norm = " ".join(t for t in lowered[i:i + size] if t)
                if not norm or norm in self.blocklist or norm in self.private:
                    continue
                if norm in self.aliases or (norm in single and size >= 1):
                    company = self.by_ticker_company((self.aliases.get(norm) or single[norm]), 1.0, "watchlist")
                elif len(norm.split()) >= 2 and len(self.by_norm.get(norm, ())) == 1:
                    cik = next(iter(self.by_norm[norm]))
                    company = Company(self.by_cik[cik][0], cik, self.by_cik[cik][1], self.by_cik[cik][2], 1.0, "text")
                else:
                    continue
                if company and company.ticker not in found:
                    found[company.ticker] = company
        return sorted(found.values(), key=lambda c: c.ticker)

    def exposure_ticker(self, vendor: str | None) -> str | None:
        norm = normalize((vendor or "").replace("_", " "))
        if not norm or norm in self.private:
            return None
        return self.exposure.get(norm) or self.exposure_compact.get(norm.replace(" ", ""))

    def benchmark(self, ticker: str) -> str:
        return "CIBR" if ticker.upper() in self.tracked else "SPY"
