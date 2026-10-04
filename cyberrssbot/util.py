from __future__ import annotations

import re
from datetime import datetime, timezone

_LEAD_SYMBOL_RE = re.compile(r"^[^\w\"'“‘(\[$€£#@]+")
_CLAIM_RE = re.compile(r"^(?P<group>.+?)\s+has just published a new victim\s*:\s*(?P<victim>.+?)\s*$", re.IGNORECASE)


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


def clean_title(text: str | None) -> str:
    return _LEAD_SYMBOL_RE.sub("", " ".join((text or "").split()))


def parse_claim(title: str | None) -> dict | None:
    match = _CLAIM_RE.match(clean_title(title))
    if not match or not match["group"].strip() or not match["victim"].strip():
        return None
    return {"group": match["group"].strip(), "victim": match["victim"].strip()}


def claim_title(claim: dict) -> str:
    return f"{claim['group']} claims {claim['victim']}"


def truncate(text: str | None, limit: int) -> str:
    text = (text or "").strip()
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"
