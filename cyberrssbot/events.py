from __future__ import annotations

import json
import logging
import time
from datetime import date, datetime, time as dtime, timedelta

from .market import NY, OPEN, MarketCalendar
from .util import parse_time

log = logging.getLogger(__name__)

EVENT_TYPES = {
    "sec.8k.1_05": "8-K Item 1.05: material cybersecurity incident",
    "sec.8k.1_05_amendment": "8-K/A amending an Item 1.05 disclosure",
    "sec.8k.8_01_cyber": "8-K Item 8.01 voluntary disclosure that mentions a cyber incident",
    "earnings.report": "8-K Item 2.02 earnings results",
    "mna.announce": "Merger or acquisition announced",
    "ransomware.claim.public": "Ransomware leak-site claim against a listed company",
    "breach.news.public": "Breach story covered by 2 or more outlets naming a listed company",
    "kev.vendor": "CISA KEV entry for a product of an exposure-mapped vendor",
    "vuln.vendor_critical": "Exploited or CVSS 9+ vulnerability in a mapped vendor's product, covered by 2+ outlets",
    "pressure.spike": "Vendor vulnerability pressure 2+ standard deviations above the ticker's own history",
    "move.unexplained": "Idiosyncratic price move with no recorded event in the previous 72 hours",
    "insider.open_buy": "Insider open-market purchase (Form 4 code P, not under a 10b5-1 plan)",
    "insider.cluster_sell": "3+ insiders selling outside 10b5-1 plans within 10 sessions",
    "ownership.13d": "Schedule 13D or 13D/A: activist stake of 5% or more",
    "tone.shift": "Earnings release tone 1.5+ standard deviations from the prior 8 releases",
    "guidance.raise": "Guidance or outlook raised",
    "guidance.cut": "Guidance or outlook lowered or withdrawn",
    "guidance.reaffirm": "Guidance or outlook reaffirmed",
    "strategic.review": "Review of strategic alternatives announced",
}
TIMINGS = ("pre", "intraday", "post", "closed")


def effective_session(when: datetime, calendar: MarketCalendar) -> tuple[date, str]:
    ny = when.astimezone(NY)
    day = ny.date()
    session = calendar.session(day)
    if session is None:
        return _next_trading_day(day, calendar), "closed"
    open_at, close_at = session
    if ny < open_at:
        return day, "pre"
    if ny < close_at:
        return day, "intraday"
    return _next_trading_day(day, calendar), "post"


def date_only_session(day: date, calendar: MarketCalendar) -> tuple[date, str]:
    return _next_trading_day(day, calendar), "post" if calendar.is_trading_day(day) else "closed"


def _next_trading_day(day: date, calendar: MarketCalendar) -> date:
    for _ in range(15):
        day += timedelta(days=1)
        if calendar.is_trading_day(day):
            return day
    raise RuntimeError("no trading day in the next 15 days")


def _iso(value) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


class EventLog:
    def __init__(self, app):
        self.app = app

    async def record(self, type_: str, *, ticker: str | None, occurred_at, dedup: str, cik: int | None = None,
                     company: str | None = None, confidence: float = 1.0, refs: dict | None = None,
                     payload: dict | None = None, date_only: bool = False) -> tuple[int, bool]:
        if type_ not in EVENT_TYPES:
            raise ValueError(f"unknown event type {type_!r}")
        calendar = self.app.market
        if date_only:
            day = occurred_at if isinstance(occurred_at, date) else date.fromisoformat(str(occurred_at)[:10])
            session, timing = date_only_session(day, calendar)
            occurred = datetime.combine(day, OPEN, NY)
            payload = {**(payload or {}), "date_only": True}
        else:
            occurred = occurred_at if isinstance(occurred_at, datetime) else parse_time(str(occurred_at))
            if occurred is None:
                raise ValueError(f"bad event time {occurred_at!r}")
            session, timing = effective_session(occurred, calendar)
        return await self.app.store.event_put({
            "type": type_, "ticker": (ticker or "").upper(), "cik": cik, "company": company,
            "occurred_at": _iso(occurred), "effective_session": session.isoformat(), "session_timing": timing,
            "confidence": round(float(confidence), 3), "source_refs": refs or {}, "payload": payload or {},
            "dedup_key": dedup, "created_at": int(time.time()),
        })

    async def add_refs(self, event_id: int, refs: dict) -> None:
        await self.app.store.event_merge_refs(event_id, refs)


def describe(row: dict) -> str:
    return EVENT_TYPES.get(row["type"], row["type"])


def dumps(value) -> str:
    return json.dumps(value, sort_keys=True)
