from __future__ import annotations

import re

_SUBJECT = r"(?:full[- ]year|annual|fiscal(?: year)?(?: \d{4})?|\d{4}|quarterly|q[1-4]|first[- ]quarter|second[- ]quarter|" \
           r"third[- ]quarter|fourth[- ]quarter|revenue|financial|earnings|eps|arr)?"
_TARGET = rf"(?:its |our |the )?(?:{_SUBJECT}\s*)*(?:guidance|outlook|forecast)"
_GAP = r"(?:(?!\band\b|\bbut\b|\bwhile\b)[^.;]){0,40}?"
_PASSIVE = r"\s+(?:was|were|is|has been|have been)\s+"
GUIDANCE = (
    ("guidance.cut", re.compile(
        rf"\b(?:lower(?:s|ed|ing)?|cut(?:s|ting)?|reduc(?:es|ed|ing)|withdr(?:aws|ew|awn)|suspend(?:s|ed))\b{_GAP}\b{_TARGET}\b"
        rf"|\b{_TARGET}{_PASSIVE}(?:lowered|cut|reduced|withdrawn|suspended)\b", re.IGNORECASE)),
    ("guidance.raise", re.compile(
        rf"\b(?:rais(?:es|ed|ing)|increas(?:es|ed|ing)|boost(?:s|ed)|lift(?:s|ed)|upgrad(?:es|ed))\b{_GAP}\b{_TARGET}\b"
        rf"|\b{_TARGET}{_PASSIVE}(?:raised|increased|boosted)\b", re.IGNORECASE)),
    ("guidance.reaffirm", re.compile(
        rf"\b(?:reaffirm(?:s|ed|ing)?|reiterat(?:es|ed|ing)|maintain(?:s|ed|ing)|confirm(?:s|ed|ing))\b{_GAP}\b{_TARGET}\b",
        re.IGNORECASE)),
)
_NAME = r"((?:[A-Z][\w&'.\-]*|\d[\w&.\-]*)(?:,? (?:[A-Z][\w&'.\-]*|Inc\.?|Corp\.?|LLC|Ltd\.?|plc|of|and|&)){0,5})"
ACQUIRES = re.compile(r"\b(?i:to acquire|will acquire|has acquired|acquires|acquired|completed (?:its |the )?acquisition of|"
                      r"definitive agreement to acquire) " + _NAME)
ACQUIRED_BY = re.compile(r"\b(?i:to be acquired by|will be acquired by|agreed to be acquired by|"
                         r"definitive agreement to be acquired by) " + _NAME)
TAKE_PRIVATE = re.compile(r"\btake[- ]private\b|\bgo(?:ing)?[- ]private\b|\btaken private\b", re.IGNORECASE)
STRATEGIC = re.compile(r"\b(?:review|explor(?:e|es|ing|ation)|evaluat(?:e|es|ing|ion)) (?:of )?(?:a range of |potential )?"
                       r"strategic alternatives\b|\bstrategic review\b", re.IGNORECASE)
_SENTENCE_RE = re.compile(r"(?<=[.!?])\s+(?=[A-Z\"“])")
NOT_COMPANIES = frozenset("""new customers customer users talent data market share share shares stake assets
    capabilities technology technologies the a an its our certain additional more licenses""".split())


def guidance(text: str) -> list[str]:
    found = [kind for kind, rx in GUIDANCE if rx.search(text or "")]
    if "guidance.cut" in found and "guidance.raise" in found:
        return ["guidance.cut", "guidance.raise"]
    return found[:1]


def _clean(name: str) -> str | None:
    name = name.strip(" ,.")
    first = name.split(" ")[0].lower()
    if not name or first in NOT_COMPANIES or len(name) < 3:
        return None
    return name


def mna(text: str) -> dict | None:
    text = text or ""
    for sentence in _SENTENCE_RE.split(text):
        found = _mna_sentence(sentence)
        if found:
            return found
    return None


def _mna_sentence(text: str) -> dict | None:
    acquired_by = ACQUIRED_BY.search(text)
    if acquired_by and _clean(acquired_by.group(1)):
        return {"role": "target", "counterparty": _clean(acquired_by.group(1))}
    acquirer_of = ACQUIRES.search(text)
    if acquirer_of and _clean(acquirer_of.group(1)):
        return {"role": "acquirer", "counterparty": _clean(acquirer_of.group(1))}
    if TAKE_PRIVATE.search(text) and re.search(r"\bdefinitive (?:merger )?agreement\b|\bto be acquired\b", text, re.I):
        return {"role": "target", "counterparty": None}
    return None


def strategic_review(text: str) -> bool:
    return bool(STRATEGIC.search(text or ""))
