from __future__ import annotations

import asyncio
import logging
import re
import time
import unicodedata
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone

from . import msrc
from .market import NY
from .util import parse_time

log = logging.getLogger(__name__)

LIMIT = 128
SEPARATOR = " · "
LEVELS = ("normal", "elevated", "critical")
STATUS = {"normal": "online", "elevated": "idle", "critical": "dnd"}
PIN_KEY, PAUSE_KEY, LEVEL_KEY = "presence.pin", "presence.paused", "presence.level"
KEV_MAX_AGE_DAYS = 7
QUOTE_MAX_AGE = 45 * 60

PRESENCE_DEFAULTS = {
    "enabled": True,
    "rotate_seconds": 90,
    "evaluate_seconds": 60,
    "min_update_seconds": 30,
    "critical_hours": 2,
    "elevated_hours": 6,
    "elevated_min_cvss": 9.0,
    "earnings_within_days": 14,
    "patch_tuesday_within_days": 14,
    "kb_hours": 48,
    "fallback": "watching.",
    "lines": {
        "kev": "kev +{n} · {vendor}",
        "ransomware": "{group} · {n} in 24h",
        "unexplained": "{ticker} {pct}% · no reason found",
        "cibr": "cibr {pct}%",
        "cibr_closed": "cibr closed {pct}%",
        "patch_tuesday": "patch tuesday in {n}d",
        "patch_today": "patch tuesday · today",
        "kb": "kb{kb} · {fixed} fixed · {late} too late",
        "earnings": "{ticker} reports in {n}d",
        "earnings_today": "{ticker} reports today",
        "disclosures": "{n} disclosure{s} this month",
        "digest": "next digest {time} utc",
    },
    "reasons": {
        "kev_ransomware": "{cve} · it's being used",
        "incident": "{ticker} · disclosed",
        "exploited_vendor": "{vendor} · open",
    },
}
ORDER = ("kev", "ransomware", "unexplained", "cibr", "patch_tuesday", "kb", "earnings", "disclosures", "digest")
REASON_ORDER = ("kev_ransomware", "incident", "exploited_vendor")


def settings(cfg: dict) -> dict:
    raw = cfg.get("presence") or {}
    out = {**PRESENCE_DEFAULTS, **raw}
    for key in ("lines", "reasons"):
        out[key] = {**PRESENCE_DEFAULTS[key], **(raw.get(key) or {})}
    return out


def voice(text: str) -> str:
    kept = []
    for ch in str(text).lower():
        if ch == "!":
            continue
        if ch.isascii() or ch == "·" or unicodedata.category(ch)[0] in "LMN":
            kept.append(ch)
    out = re.sub(r"\s+", " ", "".join(kept)).strip()
    return out[:LIMIT].rstrip()


def render_line(template: str, **fields) -> str | None:
    try:
        return voice(template.format(**fields)) or None
    except (KeyError, IndexError, ValueError) as exc:
        log.warning("presence template %r can't be filled: %s", template, exc)
        return None


def signed(value: float) -> str:
    return f"{value:+.1f}"


@dataclass
class Trigger:
    kind: str
    detail: str
    when: float
    text: str | None = None
    jump: str | None = None


@dataclass
class Level:
    name: str = "normal"
    triggers: list[Trigger] = field(default_factory=list)

    @property
    def rank(self) -> int:
        return LEVELS.index(self.name)

    @property
    def status(self) -> str:
        return STATUS[self.name]


class Presence:
    def __init__(self, app, setter=None, clock=time.monotonic):
        self.app = app
        self.cfg = settings(app.cfg)
        self.enabled = bool(self.cfg["enabled"])
        self.setter = setter
        self.clock = clock
        self.level = Level()
        self.pin: str | None = None
        self.paused = False
        self.rotating: tuple[str, str] | None = None
        self.live: list[tuple[str, str]] = []
        self.sent: tuple[str, str] | None = None
        self.sent_at: float | None = None
        self.rotated_at: float | None = None
        self.evaluated_at: float | None = None
        self.calls = 0

    async def load(self) -> None:
        store = self.app.store
        self.pin = await store.setting_get(PIN_KEY) or None
        self.paused = await store.setting_get(PAUSE_KEY) == "1"
        saved = await store.setting_get(LEVEL_KEY)
        self.level = Level(saved if saved in LEVELS else "normal")

    async def set_pin(self, text: str | None) -> None:
        self.pin = text or None
        if self.pin:
            await self.app.store.setting_set(PIN_KEY, self.pin)
        else:
            await self.app.store.setting_delete(PIN_KEY)

    async def set_paused(self, paused: bool) -> None:
        self.paused = paused
        await self.app.store.setting_set(PAUSE_KEY, "1" if paused else "0")

    # ---- threat level -----------------------------------------------------------------------
    def _watched_company(self, ticker: str) -> bool:
        return ticker in self.app.finance.watch.companies or ticker in self.app.companies.tracked

    def _watched_vendor(self, d: dict) -> bool:
        return self.app.vulns.watched(d) or bool(self.app.companies.exposure_ticker(d.get("vendor")))

    async def kev_additions(self, since: float, now: datetime) -> list[dict]:
        out = []
        for row in await self.app.store.vulns_touched(since):
            kev = row["data"].get("kev") or {}
            if not kev or (kev.get("seen") or 0) < since or kev["seen"] > now.timestamp():
                continue
            added = parse_time(kev.get("date_added"))
            if added and (now.date() - added.date()).days > KEV_MAX_AGE_DAYS:
                continue
            out.append(row)
        return sorted(out, key=lambda r: r["data"]["kev"]["seen"])

    async def evaluate(self, now: datetime) -> Level:
        app, cfg = self.app, self.cfg
        ts = now.timestamp()
        critical_since = ts - float(cfg["critical_hours"]) * 3600
        elevated_since = ts - float(cfg["elevated_hours"]) * 3600
        reasons = cfg["reasons"]
        critical, elevated = [], []

        touched = await app.store.vulns_touched(elevated_since)
        for row in await self.kev_additions(elevated_since, now):
            d, kev = row["data"], row["data"]["kev"]
            cve = row["vid"]
            jump = app.poster.jump_url(row["channel_id"], row["message_id"])
            elevated.append(Trigger("kev", f"{cve} added to kev", kev["seen"], jump=jump))
            if kev["seen"] < critical_since:
                continue
            if str(kev.get("ransomware") or "").lower() == "known":
                critical.append(Trigger("kev_ransomware", f"{cve} added to kev with known ransomware use", kev["seen"],
                                        render_line(reasons["kev_ransomware"], cve=cve), jump))
            if self._watched_vendor(d):
                vendor = d.get("vendor") or cve
                critical.append(Trigger("exploited_vendor", f"{cve} exploited in {vendor}", kev["seen"],
                                        render_line(reasons["exploited_vendor"], vendor=vendor, cve=cve), jump))

        for ev in await app.store.events_query(type_="sec.8k.1_05", since=(now - timedelta(days=4)).date().isoformat()):
            when = parse_time(ev["occurred_at"])
            if when is None or not critical_since <= when.timestamp() <= ts or not self._watched_company(ev["ticker"]):
                continue
            post = ev["source_refs"].get("message")
            critical.append(Trigger("incident", f"{ev['ticker']} filed an 8-k item 1.05", when.timestamp(),
                                    render_line(reasons["incident"], ticker=ev["ticker"]),
                                    app.poster.jump_url(*post) if post else ev["source_refs"].get("filing")))

        for row in touched:
            score = row["data"].get("cvss") or 0
            if row["posted"] == 1 and score >= float(cfg["elevated_min_cvss"]) and row["first_seen"] >= elevated_since \
                    and row["first_seen"] <= ts:
                elevated.append(Trigger("cvss", f"{row['vid']} posted with cvss {score:g}", row["first_seen"],
                                        jump=app.poster.jump_url(row["channel_id"], row["message_id"])))
        for key, seen in await app.store.seen_since("fin:alert:", elevated_since):
            parts = key.split(":")
            if seen <= ts and len(parts) >= 4:
                elevated.append(Trigger("move", f"{parts[3]} move alert", seen))

        if critical:
            critical.sort(key=lambda t: (REASON_ORDER.index(t.kind), -t.when))
            return Level("critical", [t for t in critical if t.text] or critical)
        if elevated:
            return Level("elevated", sorted(elevated, key=lambda t: -t.when))
        return Level()

    async def announce(self, old: Level, new: Level) -> None:
        trigger = new.triggers[0]
        parts = [f"threat level {new.name}", f"was {old.name}", voice(trigger.detail)]
        if trigger.jump:
            parts.append(trigger.jump)
        await self.app.poster.send("log", content=SEPARATOR.join(parts), fallback=False)

    # ---- rotating lines ---------------------------------------------------------------------
    async def lines(self, now: datetime) -> list[tuple[str, str]]:
        out = []
        for key in ORDER:
            try:
                text = await getattr(self, f"_line_{key}")(now)
            except Exception:
                log.exception("presence line %s failed", key)
                text = None
            if text:
                out.append((key, text))
        return out

    def _template(self, key: str) -> str:
        return self.cfg["lines"][key]

    async def _line_kev(self, now: datetime) -> str | None:
        start = now.replace(hour=0, minute=0, second=0, microsecond=0).timestamp()
        rows = await self.kev_additions(start, now)
        if not rows:
            return None
        vendor = rows[-1]["data"].get("vendor") or rows[-1]["vid"]
        return render_line(self._template("kev"), n=len(rows), vendor=vendor)

    async def _line_ransomware(self, now: datetime) -> str | None:
        counts: dict[str, int] = {}
        for row in await self.app.store.stories_between(now.timestamp() - 86400, now.timestamp() + 1):
            group = (row["data"].get("claim") or {}).get("group")
            if group:
                counts[group] = counts.get(group, 0) + 1
        if not counts:
            return None
        group, n = min(counts.items(), key=lambda item: (-item[1], item[0].lower()))
        return render_line(self._template("ransomware"), group=group, n=n)

    async def _line_unexplained(self, now: datetime) -> str | None:
        today = now.astimezone(NY).date()
        moves = []
        for ev in await self.app.store.events_query(type_="move.unexplained", since=today.isoformat()):
            when = parse_time(ev["occurred_at"])
            if when and when <= now and when.astimezone(NY).date() == today and ev["payload"].get("dp") is not None:
                moves.append((when, ev))
        if not moves:
            return None
        ev = max(moves, key=lambda item: item[0])[1]
        return render_line(self._template("unexplained"), ticker=ev["ticker"], pct=signed(float(ev["payload"]["dp"])))

    async def _line_cibr(self, now: datetime) -> str | None:
        session = self.app.market.session(now.astimezone(NY).date())
        quote = await self.app.store.quote_get("CIBR")
        if session is None or quote is None or quote[0].get("dp") is None:
            return None
        open_at, close_at = session
        data, ts = quote
        pct = signed(float(data["dp"]))
        if open_at <= now <= close_at:
            if ts >= open_at.timestamp() and now.timestamp() - ts <= QUOTE_MAX_AGE:
                return render_line(self._template("cibr"), pct=pct)
            return None
        if now > close_at and ts >= close_at.timestamp() - QUOTE_MAX_AGE:
            return render_line(self._template("cibr_closed"), pct=pct)
        return None

    def _patch_release(self, day: date) -> datetime:
        return datetime.combine(msrc.patch_tuesday(day.year, day.month), msrc.RELEASE_TIME, tzinfo=msrc.PACIFIC)

    async def _line_patch_tuesday(self, now: datetime) -> str | None:
        today = now.astimezone(msrc.PACIFIC).date()
        tuesday = msrc.patch_tuesday(today.year, today.month)
        if tuesday < today:
            following = (today.replace(day=1) + timedelta(days=32)).replace(day=1)
            tuesday = msrc.patch_tuesday(following.year, following.month)
        days = (tuesday - today).days
        if days == 0:
            return render_line(self._template("patch_today"))
        if days > int(self.cfg["patch_tuesday_within_days"]):
            return None
        return render_line(self._template("patch_tuesday"), n=days)

    async def _line_kb(self, now: datetime) -> str | None:
        release = self._patch_release(now.astimezone(msrc.PACIFIC).date())
        if release > now:
            release = self._patch_release(release.date().replace(day=1) - timedelta(days=1))
        if not timedelta(0) <= now - release <= timedelta(hours=float(self.cfg["kb_hours"])):
            return None
        rows = [r for r in await self.app.store.ms_kbs_between(release.timestamp() - 3600, now.timestamp() + 1)
                if r["data"].get("cves")]
        if not rows:
            return None
        row = min(rows, key=lambda r: (-len(r["data"]["cves"]), r["kb"]))
        counts = msrc.kb_counts(row["data"])
        return render_line(self._template("kb"), kb=row["kb"], fixed=counts["cves"], late=counts["exploited"])

    async def _line_earnings(self, now: datetime) -> str | None:
        today = now.astimezone(NY).date()
        horizon = today + timedelta(days=int(self.cfg["earnings_within_days"]))
        rows = sorted(await self.app.store.earnings_between(today.isoformat(), horizon.isoformat()),
                      key=lambda r: (r["date"], r["symbol"]))
        if not rows:
            return None
        days = (date.fromisoformat(rows[0]["date"]) - today).days
        if days == 0:
            return render_line(self._template("earnings_today"), ticker=rows[0]["symbol"])
        return render_line(self._template("earnings"), ticker=rows[0]["symbol"], n=days)

    async def _line_disclosures(self, now: datetime) -> str | None:
        month = now.strftime("%Y-%m")
        since = (now.replace(day=1) - timedelta(days=4)).date().isoformat()
        n = 0
        for ev in await self.app.store.events_query(type_="sec.8k.1_05", since=since):
            when = parse_time(ev["occurred_at"])
            if when and when <= now and when.astimezone(timezone.utc).strftime("%Y-%m") == month:
                n += 1
        if not n:
            return None
        return render_line(self._template("disclosures"), n=n, s="" if n == 1 else "s")

    async def _line_digest(self, now: datetime) -> str | None:
        runner = self.app.digest
        if not runner.cfg.get("enabled"):
            return None
        upcoming = runner.upcoming(now)
        if not upcoming:
            return None
        return render_line(self._template("digest"), time=upcoming[0][2].strftime("%H:%M"))

    def next_line(self, live: list[tuple[str, str]]) -> tuple[str, str]:
        if not live:
            return "fallback", voice(self.cfg["fallback"])
        by_key = dict(live)
        last = self.rotating[0] if self.rotating else None
        start = ORDER.index(last) + 1 if last in ORDER else 0
        for key in ORDER[start:] + ORDER[:start]:
            if key in by_key:
                return key, by_key[key]
        return live[0]

    # ---- output -----------------------------------------------------------------------------
    async def tick(self, now: datetime | None = None) -> bool:
        now = now or datetime.now(timezone.utc)
        mono = self.clock()
        if self.evaluated_at is None or mono - self.evaluated_at >= float(self.cfg["evaluate_seconds"]):
            self.evaluated_at = mono
            new = await self.evaluate(now)
            old, self.level = self.level, new
            if new.name != old.name:
                await self.app.store.setting_set(LEVEL_KEY, new.name)
                if new.rank > old.rank:
                    await self.announce(old, new)

        reason = self.level.triggers[0].text if self.level.name == "critical" and self.level.triggers else None
        if not self.pin and not reason:
            due = self.rotated_at is None or mono - self.rotated_at >= float(self.cfg["rotate_seconds"])
            if self.rotating is None or due:
                self.live = await self.lines(now)
                self.rotating = self.next_line(self.live)
                self.rotated_at = mono
        text = self.pin or reason or self.rotating[1]
        return await self.apply(self.level.status, text[:LIMIT])

    async def apply(self, status: str, text: str) -> bool:
        if self.paused or self.setter is None or (status, text) == self.sent:
            return False
        mono = self.clock()
        if self.sent_at is not None and mono - self.sent_at < float(self.cfg["min_update_seconds"]):
            return False
        await self.setter(status, text)
        self.sent, self.sent_at = (status, text), mono
        self.calls += 1
        return True

    async def describe(self, now: datetime | None = None) -> str:
        now = now or datetime.now(timezone.utc)
        level = await self.evaluate(now)
        live = await self.lines(now)
        out = [f"level: {level.name} ({level.status})"]
        out.append("why: " + (SEPARATOR.join(voice(t.detail) for t in level.triggers[:5]) or "nothing in the window"))
        out.append(f"showing: {self.sent[1] if self.sent else 'nothing yet'}")
        out.append(f"pin: {self.pin or 'none'}{SEPARATOR}paused: {'yes' if self.paused else 'no'}")
        out.append("live lines:")
        out += [f"- {key}: {text}" for key, text in live] or [f"- none, so the fallback: {voice(self.cfg['fallback'])}"]
        return "\n".join(out)

    async def loop(self) -> None:
        await self.load()
        while True:
            try:
                await self.tick()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("presence loop error")
            await asyncio.sleep(10)
