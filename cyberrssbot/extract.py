from __future__ import annotations

import re
from dataclasses import dataclass, field

from .dedup import CVE_RE
from .kb import TYPE_ORDER, KnowledgeBase

ACTIONS = ("arrested", "indicted", "exploited", "breached", "patched", "fined", "acquired")
CURRENCY_SYMBOLS = {"US$": "USD", "A$": "AUD", "C$": "CAD", "$": "USD", "€": "EUR", "£": "GBP", "₹": "INR",
                    "¥": "JPY"}
CURRENCY_WORDS = {"usd": "USD", "dollars": "USD", "dollar": "USD", "eur": "EUR", "euros": "EUR", "euro": "EUR",
                  "gbp": "GBP", "pounds": "GBP", "inr": "INR", "rupees": "INR", "btc": "BTC", "bitcoin": "BTC",
                  "bitcoins": "BTC", "eth": "ETH"}
MULTIPLIERS = {"k": 1e3, "thousand": 1e3, "m": 1e6, "mn": 1e6, "million": 1e6, "b": 1e9, "bn": 1e9,
               "billion": 1e9, "trillion": 1e12, "lakh": 1e5, "crore": 1e7}
COUNT_UNITS = {
    "victims": ("people", "individuals", "customers", "users", "patients", "victims", "employees", "students",
                "members", "residents", "citizens", "subscribers", "clients", "consumers", "households"),
    "records": ("records", "accounts", "files", "emails", "passwords", "credentials", "documents", "cards"),
    "devices": ("devices", "servers", "systems", "routers", "hosts", "machines", "endpoints", "firewalls",
                "cameras", "computers", "phones", "instances", "websites", "sites", "domains", "appliances"),
    "organizations": ("organizations", "organisations", "companies", "businesses", "hospitals", "schools",
                      "agencies", "banks"),
}
UNIT_KIND = {unit: kind for kind, units in COUNT_UNITS.items() for unit in units}
VERSION_WORDS = {"windows", "ios", "android", "macos", "server", "office", "chrome", "firefox", "version",
                 "python", "php", "java", "top", "cvss", "port", "ubuntu", "debian", "exchange", "sharepoint",
                 "ipados", "watchos", "visionos", "v", "build", "kb", "about"}

_NUM = r"\d[\d,]*(?:\.\d+)?"
_MULT = r"(?:thousand|million|billion|trillion|crore|lakh|mn|bn|k|m|b)"
_MONEY_SYMBOL_RE = re.compile(
    rf"(?P<sym>US\$|A\$|C\$|\$|€|£|₹|¥)\s?(?P<num>{_NUM})(?:\s?(?P<mult>{_MULT})\b)?", re.IGNORECASE)
_MONEY_WORD_RE = re.compile(
    rf"(?<![\w$€£₹¥.,])(?P<num>{_NUM})(?:\s?(?P<mult>{_MULT})\b)?\s?"
    rf"(?P<cur>USD|EUR|GBP|INR|BTC|ETH|dollars?|euros?|pounds|rupees|bitcoins?)\b", re.IGNORECASE)
_MONEY_CODE_RE = re.compile(
    rf"\b(?P<cur>USD|EUR|GBP|INR)\s?(?P<num>{_NUM})(?:\s?(?P<mult>{_MULT})\b)?", re.IGNORECASE)
_QUALIFIER = (r"(?:of|more|other|additional|unique|affected|impacted|exposed|vulnerable|compromised|infected|"
              r"internet-facing|internet-exposed|unpatched|customer|patient|user|medical|personal|sensitive|"
              r"stolen|leaked|employee|current|former|active|hacked|its|their|the)")
_COUNT_RE = re.compile(
    rf"(?<![\w$€£₹¥.,-])(?P<num>{_NUM})(?:\s?(?P<mult>thousand|million|billion|k|m)\b)?\+?\s+"
    rf"(?:{_QUALIFIER}\s+){{0,3}}(?P<unit>{'|'.join(sorted(UNIT_KIND, key=len, reverse=True))})\b", re.IGNORECASE)
_YEAR_RE = re.compile(r"(?:19|20)\d\d")
_WORD_BEFORE_RE = re.compile(r"([\w.]+)\W*$")

_ACTION_RES = {
    "arrested": re.compile(r"(?<!cardiac )\barrest(?:s|ed|ing)?\b|\bapprehended\b|\bdetained\b|\bin custody\b|"
                           r"\bextradited\b", re.IGNORECASE),
    "indicted": re.compile(r"\bindict(?:s|ed|ment|ments)\b|\bcharged (?:with|over|in|for)\b|\bcharges (?:against|"
                           r"filed)\b|\bpleads? guilty\b|\bpleaded guilty\b|\bconvicted\b|\bsentenced\b",
                           re.IGNORECASE),
    "exploited": re.compile(r"\bexploit(?:s|ed|ing)\b|\bexploit (?!kits?\b|code\b|chains?\b|brokers?\b)|\b(?:active|mass|ongoing) exploitation\b|"
                            r"\bexploitation (?:of|in|attempts|detected)\b|\bin[- ]the[- ]wild\b|"
                            r"\bunder (?:active )?attack\b", re.IGNORECASE),
    "breached": re.compile(r"\bbreach(?:ed|es)?\b|\bhacked\b|\bcompromised\b|\bdata (?:leak|theft)\b|"
                           r"\bleak(?:ed|s)\b|\bexfiltrated\b|\bstole\b|\bstolen\b", re.IGNORECASE),
    "patched": re.compile(r"\bpatch(?:es|ed)?\b|\bfix(?:es|ed)\b|\bhotfix\b|\bsecurity updates?\b|"
                          r"\bmitigat(?:ion|ions|ed|es)\b", re.IGNORECASE),
    "fined": re.compile(r"\bfined\b|\bfines (?![a-z]+ (?:line|print))|\bfine of\b|(?:[$€£₹]|\d)[\w.,]* fine\b|"
                        r"\bpenalt(?:y|ies)\b|\bto pay [$€£₹]", re.IGNORECASE),
    "acquired": re.compile(r"\bacquir(?:e|es|ed|ing)\b|\bacquisition\b|\bto buy\b|\bbuys\b|\bbought\b|"
                           r"\bmerger\b|\btakeover\b", re.IGNORECASE),
}


@dataclass
class Extraction:
    entities: dict[str, list[str]] = field(default_factory=lambda: {t: [] for t in TYPE_ORDER})
    cves: list[str] = field(default_factory=list)
    money: list[dict] = field(default_factory=list)
    counts: list[dict] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)
    spans: list[tuple[int, int]] = field(default_factory=list)
    ransomware: bool = False

    def named(self) -> list[str]:
        return self.entities["actor"] + self.entities["malware"]

    def as_dict(self) -> dict:
        return {"entities": {k: v for k, v in self.entities.items() if v}, "cves": self.cves, "money": self.money,
                "counts": self.counts, "actions": self.actions}


def _number(num: str, mult: str | None) -> float:
    return float(num.replace(",", "")) * MULTIPLIERS.get((mult or "").lower(), 1)


def find_money(text: str) -> list[tuple[int, int, dict]]:
    out = []
    for match in _MONEY_SYMBOL_RE.finditer(text):
        out.append((match.start(), match.end(), {
            "amount": _number(match["num"], match["mult"]),
            "currency": CURRENCY_SYMBOLS[match["sym"].upper()], "text": match.group().strip()}))
    for pattern in (_MONEY_CODE_RE, _MONEY_WORD_RE):
        taken = [(s, e) for s, e, _ in out]
        for match in pattern.finditer(text):
            if any(s < match.end() and match.start() < e for s, e in taken):
                continue
            out.append((match.start(), match.end(), {
                "amount": _number(match["num"], match["mult"]),
                "currency": CURRENCY_WORDS[match["cur"].lower()], "text": match.group().strip()}))
    return sorted(out, key=lambda item: item[0])


def find_counts(text: str, money: list[tuple[int, int, dict]]) -> list[tuple[int, int, dict]]:
    out = []
    for match in _COUNT_RE.finditer(text):
        if any(s <= match.start() < e for s, e, _ in money):
            continue
        raw, mult = match["num"], match["mult"]
        value = _number(raw, mult)
        if value < 100 or (not mult and "," not in raw and _YEAR_RE.fullmatch(raw)):
            continue
        before = _WORD_BEFORE_RE.search(text[:match.start()])
        if before and before.group(1).lower().rstrip(".") in VERSION_WORDS:
            continue
        unit = match["unit"].lower()
        end = match.end()
        out.append((match.start(), end, {"value": int(value), "unit": unit, "kind": UNIT_KIND[unit],
                                         "text": match.group().strip()}))
    return out


def find_actions(text: str) -> list[str]:
    return [action for action in ACTIONS if _ACTION_RES[action].search(text)]


def extract(text: str, kb: KnowledgeBase) -> Extraction:
    out = Extraction()
    text = text or ""
    spans = []
    for match in kb.find(text):
        names = out.entities[match.entity.type]
        if match.entity.name not in names:
            names.append(match.entity.name)
        if match.entity.type == "actor" and match.entity.kind == "ransomware":
            out.ransomware = True
        spans.append((match.start, match.end))
    for match in CVE_RE.finditer(text):
        cve = match.group().upper()
        if cve not in out.cves:
            out.cves.append(cve)
        spans.append((match.start(), match.end()))
    money = find_money(text)
    counts = find_counts(text, money)
    out.money = [m for _, _, m in money]
    out.counts = [c for _, _, c in counts]
    spans += [(s, e) for s, e, _ in money] + [(s, e) for s, e, _ in counts]
    out.actions = find_actions(text)

    merged: list[tuple[int, int]] = []
    for start, end in sorted(spans):
        if merged and start < merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    out.spans = merged
    return out
