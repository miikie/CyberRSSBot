from __future__ import annotations

import hashlib
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

TRACKING_KEYS = {
    "fbclid", "gclid", "dclid", "msclkid", "mc_cid", "mc_eid", "ref", "ref_src", "cmpid", "ncid",
    "sr_share", "guccounter", "_hsenc", "_hsmi", "mkt_tok", "spm", "taid", "at_medium", "at_campaign",
}


def canonical_url(url: str) -> str:
    url = (url or "").strip()
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    host = (parts.hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    path = re.sub(r"/{2,}", "/", parts.path or "/")
    path = re.sub(r"/amp/?$", "/", path)
    if len(path) > 1:
        path = path.rstrip("/")
    query = sorted(
        (k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
        if not (k.lower().startswith("utm_") or k.lower() in TRACKING_KEYS)
    )
    return urlunsplit(("https", host, path, urlencode(query), ""))


def key_hash(value: str) -> str:
    return hashlib.sha1(value.encode("utf-8", "replace")).hexdigest()[:24]


STOPWORDS = frozenset("""
a an the and or but of in on at to for from by with without into over under about after before
as is are was were be been being it its this that these those via vs new now how why what who
when where you your their our his her they we i us not no than more most just also amid against
says said here heres could may might will would can up out off
""".split())

_SUFFIXES = ("ations", "ation", "ities", "ings", "ity", "ing", "ers", "ies", "ly", "er", "ed", "es", "s")
_SITE_SUFFIX_RE = re.compile(r"\s+[|–—-]\s+[^|–—-]{2,40}$")
_TOKEN_RE = re.compile(r"[a-z0-9]+(?:[-.][a-z0-9]+)*")


def _stem(tok: str) -> str:
    if "-" in tok or any(c.isdigit() for c in tok) or len(tok) <= 4:
        return tok
    for suf in _SUFFIXES:
        if tok.endswith(suf) and len(tok) - len(suf) >= 4:
            tok = tok[: -len(suf)]
            break
    if tok.endswith("e") and len(tok) > 4:
        tok = tok[:-1]
    return tok


GENERIC = frozenset(_stem(w) for w in """
hacker hackers hack hacked attack attacks attacker attackers exploit exploited exploits exploitation
zero-day zero-days 0-day vulnerability vulnerabilities flaw flaws bug bugs patch patches patched
update updates fix fixes fixed critical severe warns warn warning alert alerts active actively
report reports researchers researcher malware ransomware breach breached data cyber cyberattack
threat threats actor actors campaign campaigns target targets targeting user users customers
millions security issue issues release released urgent abuse abused compromise compromised
rce remote code execution attacks new exposed leak leaked steal stolen group gang
""".split())
COMMON = frozenset(_stem(w) for w in "microsoft google apple windows linux android chrome".split())


def fingerprint(title: str, extra_text: str = "") -> tuple[frozenset, frozenset]:
    cves = frozenset(c.upper() for c in CVE_RE.findall(f"{title} {extra_text}"))
    text = _SITE_SUFFIX_RE.sub("", (title or "").strip()).lower()
    text = text.replace("\u2019", "'").replace("'s ", " ")
    tokens = frozenset(_stem(w) for w in _TOKEN_RE.findall(text) if w not in STOPWORDS and len(w) > 1)
    return tokens, cves


def _weight(tok: str) -> float:
    return 0.3 if tok in GENERIC else 0.6 if tok in COMMON else 1.0


def similarity(a: frozenset, b: frozenset) -> float:
    union = a | b
    if not union:
        return 0.0
    return sum(_weight(t) for t in a & b) / sum(_weight(t) for t in union)


class StoryIndex:
    def __init__(self, window_seconds: float, threshold: float, cve_threshold: float):
        self.window = window_seconds
        self.threshold = threshold
        self.cve_threshold = cve_threshold
        self._entries: list[tuple[int, float, frozenset, frozenset]] = []

    def add(self, sid: int, ts: float, tokens, cves) -> None:
        self._entries.append((sid, ts, frozenset(tokens), frozenset(cves)))

    def find(self, tokens: frozenset, cves: frozenset, now: float) -> int | None:
        self._entries = [e for e in self._entries if now - e[1] <= self.window]
        best, best_score = None, 0.0
        for sid, _, other_tokens, other_cves in self._entries:
            if tokens and tokens == other_tokens:
                return sid
            score = similarity(tokens, other_tokens)
            shared_cve = bool(cves & other_cves)
            long_enough = min(len(tokens), len(other_tokens)) >= 3
            if (shared_cve and score >= self.cve_threshold) or (long_enough and score >= self.threshold):
                if score > best_score:
                    best, best_score = sid, score
        return best
