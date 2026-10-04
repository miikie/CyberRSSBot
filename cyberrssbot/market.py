from __future__ import annotations

from datetime import date, datetime, time, timedelta
from zoneinfo import ZoneInfo

NY = ZoneInfo("America/New_York")
OPEN = time(9, 30)
CLOSE = time(16, 0)
EARLY_CLOSE = time(13, 0)
ONE_OFF_CLOSURES = (date(2025, 1, 9),)


def _nth_weekday(year: int, month: int, weekday: int, n: int) -> date:
    d = date(year, month, 1)
    d += timedelta(days=(weekday - d.weekday()) % 7)
    return d + timedelta(weeks=n - 1)


def _last_weekday(year: int, month: int, weekday: int) -> date:
    d = (date(year, month + 1, 1) if month < 12 else date(year + 1, 1, 1)) - timedelta(days=1)
    return d - timedelta(days=(d.weekday() - weekday) % 7)


def _easter(year: int) -> date:
    a = year % 19
    b, c = divmod(year, 100)
    d, e = divmod(b, 4)
    f = (b + 8) // 25
    g = (b - f + 1) // 3
    h = (19 * a + b - d - g + 15) % 30
    i, k = divmod(c, 4)
    l = (32 + 2 * e + 2 * i - h - k) % 7
    m = (a + 11 * h + 22 * l) // 451
    month, day = divmod(h + l - 7 * m + 114, 31)
    return date(year, month, day + 1)


def _observed(d: date) -> date:
    if d.weekday() == 5:
        return d - timedelta(days=1)
    if d.weekday() == 6:
        return d + timedelta(days=1)
    return d


def nyse_holidays(year: int) -> dict[date, time | None]:
    days: dict[date, time | None] = {}
    new_year = date(year, 1, 1)
    if new_year.weekday() != 5:
        days[_observed(new_year)] = None
    days[_nth_weekday(year, 1, 0, 3)] = None
    days[_nth_weekday(year, 2, 0, 3)] = None
    days[_easter(year) - timedelta(days=2)] = None
    days[_last_weekday(year, 5, 0)] = None
    if year >= 2022:
        days[_observed(date(year, 6, 19))] = None
    days[_observed(date(year, 7, 4))] = None
    days[_nth_weekday(year, 9, 0, 1)] = None
    thanksgiving = _nth_weekday(year, 11, 3, 4)
    days[thanksgiving] = None
    days[_observed(date(year, 12, 25))] = None
    days[thanksgiving + timedelta(days=1)] = EARLY_CLOSE
    for eve in (date(year, 7, 3), date(year, 12, 24)):
        if eve.weekday() <= 3 and eve not in days:
            days[eve] = EARLY_CLOSE
    for closed in ONE_OFF_CLOSURES:
        if closed.year == year:
            days[closed] = None
    return days


class MarketCalendar:
    def __init__(self):
        self.overrides: dict[date, time | None] = {}
        self._rules: dict[int, dict[date, time | None]] = {}

    def load_finnhub(self, rows: list[dict]) -> int:
        loaded = 0
        for row in rows or []:
            try:
                day = date.fromisoformat(row["atDate"])
            except (KeyError, TypeError, ValueError):
                continue
            hours = (row.get("tradingHour") or "").strip()
            if hours:
                try:
                    hh, mm = hours.split("-")[-1].strip().split(":")
                    self.overrides[day] = time(int(hh), int(mm))
                except ValueError:
                    continue
            else:
                self.overrides[day] = None
            loaded += 1
        return loaded

    def close_time(self, day: date) -> time | None:
        if day.weekday() >= 5:
            return None
        if day in self.overrides:
            return self.overrides[day]
        rules = self._rules.setdefault(day.year, nyse_holidays(day.year))
        if day in rules:
            return rules[day]
        return CLOSE

    def is_trading_day(self, day: date) -> bool:
        return self.close_time(day) is not None

    def session(self, day: date) -> tuple[datetime, datetime] | None:
        close = self.close_time(day)
        if close is None:
            return None
        return datetime.combine(day, OPEN, NY), datetime.combine(day, close, NY)

    def next_session(self, after: datetime) -> tuple[datetime, datetime]:
        day = after.astimezone(NY).date()
        for _ in range(15):
            s = self.session(day)
            if s and s[1] > after:
                return s
            day += timedelta(days=1)
        raise RuntimeError("no trading session in the next 15 days")
