from __future__ import annotations

from datetime import datetime, timezone


def parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def primary_id(data: dict) -> str:
    for ident in [data["id"], *data.get("aliases", [])]:
        if ident.upper().startswith("CVE-"):
            return ident.upper()
    return data["id"]


def truncate(text: str | None, limit: int) -> str:
    text = (text or "").strip()
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"
