from __future__ import annotations

import bisect
import re
import xml.etree.ElementTree as ET
from datetime import date

CLUSTER_SESSIONS = 10
CLUSTER_MIN_INSIDERS = 3
_PLAN_RE = re.compile(r"10b5-1|10b5 - 1|10b5‑1", re.IGNORECASE)
_COVER_RE = re.compile(r"sell[- ]to[- ]cover|to cover (?:the |applicable |any )?(?:payment of )?(?:\w+ )?tax|"
                       r"tax[- ]withholding|withholding (?:tax|obligations?)|satisfy (?:the |his |her |their |any )?"
                       r"(?:\w+ )?(?:tax|withholding)|tax obligations? (?:arising|in connection|upon|due)",
                       re.IGNORECASE)


def _text(node, path: str) -> str | None:
    found = node.find(path)
    if found is None:
        return None
    value = found.findtext("value") if found.find("value") is not None else found.text
    return value.strip() if value and value.strip() else None


def _number(node, path: str) -> float | None:
    value = _text(node, path)
    try:
        return float(value.replace(",", "")) if value else None
    except ValueError:
        return None


def parse_form4(xml: bytes | str) -> dict:
    root = ET.fromstring(xml if isinstance(xml, bytes) else xml.encode("utf-8"))
    for el in root.iter():
        if "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]
    owners = []
    for owner in root.findall("reportingOwner"):
        rel = owner.find("reportingOwnerRelationship")
        roles = []
        if rel is not None:
            if (rel.findtext("isDirector") or "").strip() in ("1", "true"):
                roles.append("director")
            if (rel.findtext("isOfficer") or "").strip() in ("1", "true"):
                roles.append((rel.findtext("officerTitle") or "officer").strip() or "officer")
            if (rel.findtext("isTenPercentOwner") or "").strip() in ("1", "true"):
                roles.append("10% owner")
        owners.append({"cik": (owner.findtext("reportingOwnerId/rptOwnerCik") or "").strip(),
                       "name": (owner.findtext("reportingOwnerId/rptOwnerName") or "").strip(), "roles": roles})
    footnotes = {fn.get("id"): " ".join(fn.itertext()) for fn in root.findall("footnotes/footnote")}
    checkbox = (root.findtext("aff10b5One") or "").strip()
    plan_flag = None if checkbox == "" else checkbox in ("1", "true")
    remarks = " ".join((root.findtext("remarks") or "").split())
    if plan_flag is None and _PLAN_RE.search(remarks):
        plan_flag = True
    cover_all = bool(_COVER_RE.search(remarks))
    transactions = []
    for tx in root.findall("nonDerivativeTable/nonDerivativeTransaction"):
        notes = " ".join(footnotes.get(ref.get("id"), "") for ref in tx.iter("footnoteId"))
        shares = _number(tx, "transactionAmounts/transactionShares")
        price = _number(tx, "transactionAmounts/transactionPricePerShare")
        transactions.append({
            "date": (_text(tx, "transactionDate") or "")[:10],
            "code": (tx.findtext("transactionCoding/transactionCode") or "").strip(),
            "acquired": _text(tx, "transactionAmounts/transactionAcquiredDisposedCode") == "A",
            "shares": shares, "price": price,
            "value": round(shares * price, 2) if shares is not None and price is not None else None,
            "owned_after": _number(tx, "postTransactionAmounts/sharesOwnedFollowingTransaction"),
            "plan": plan_flag if plan_flag is not None else bool(_PLAN_RE.search(notes)),
            "cover": cover_all or bool(_COVER_RE.search(notes)),
        })
    if plan_flag is None and not transactions:
        plan_flag = False
    return {"schema": (root.findtext("schemaVersion") or "").strip(), "owners": owners,
            "plan_checkbox": plan_flag, "transactions": transactions,
            "issuer_cik": (root.findtext("issuer/issuerCik") or "").strip(),
            "issuer_ticker": (root.findtext("issuer/issuerTradingSymbol") or "").strip().upper()}


def open_market_buys(form: dict) -> list[dict]:
    return [t for t in form["transactions"] if t["code"] == "P" and not t["plan"]]


def unplanned_sales(form: dict) -> list[dict]:
    return [t for t in form["transactions"] if t["code"] == "S" and not t["plan"] and not t.get("cover")]


def cluster(sales: list[dict], day: str, calendar: list[str]) -> dict | None:
    end = bisect.bisect_right(calendar, day) - 1
    if end < 0:
        return None
    start_day = calendar[max(0, end - CLUSTER_SESSIONS + 1)]
    window = [s for s in sales if start_day <= s["date"] <= day]
    owners = sorted({s["owner_cik"] for s in window})
    if len(owners) < CLUSTER_MIN_INSIDERS:
        return None
    return {"start": min(s["date"] for s in window), "end": day, "owners": owners,
            "names": sorted({s["owner"] for s in window}),
            "value": round(sum(s["value"] or 0 for s in window), 2), "sales": len(window)}


def trading_days(start: date, end: date, calendar) -> list[str]:
    out, day = [], start
    while day <= end:
        if calendar.is_trading_day(day):
            out.append(day.isoformat())
        day = date.fromordinal(day.toordinal() + 1)
    return out
