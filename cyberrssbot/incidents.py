from __future__ import annotations

import logging
import re
from urllib.parse import urljoin

import feedparser
from bs4 import BeautifulSoup

from . import render
from .util import parse_time

log = logging.getLogger(__name__)

ATOM_URL = "https://www.sec.gov/cgi-bin/browse-edgar"
EFTS_URL = "https://efts.sec.gov/LATEST/search-index"
SUBMISSIONS_URL = "https://data.sec.gov/submissions/CIK{cik:010d}.json"
DEFAULT_8_01_KEYWORDS = [
    "cybersecurity incident", "cyber incident", "cyberattack", "cyber-attack", "cyber attack", "ransomware",
    "unauthorized access", "unauthorized third party", "threat actor", "data security incident",
    "information security incident", "network security incident",
]
_TITLE_RE = re.compile(r"^(?P<form>\S+)\s+-\s+(?P<company>.+?)\s+\((?P<cik>\d{10})\)")
_ITEM_RE = re.compile(r"Item\s+(\d{1,2}\.\d{2})")
_ACC_RE = re.compile(r"AccNo:\s*([\d-]+)")
_SECTION_RE = re.compile(r"item\s*(\d{1,2}\.\d{2})", re.IGNORECASE)
_WS_RE = re.compile(r"\s+")

FEATURES = (
    ("ransomware", "ransomware", re.compile(r"ransomware|encrypt(?:ed|ion) (?:of )?(?:certain )?(?:systems|files|data)", re.I)),
    ("disruption", "operations disrupted",
     re.compile(r"disrupt|outage|offline|shut (?:down|off)|took (?:certain )?(?:systems|servers) (?:offline|down)|"
                r"suspend(?:ed)? (?:certain )?operations|unable to (?:operate|process)", re.I)),
    ("exfiltration", "data taken",
     re.compile(r"exfiltrat|personal (?:data|information)|personally identifiable|protected health information|"
                r"(?:copied|acquired|obtained|stole|accessed) (?:certain )?(?:data|files|information)", re.I)),
    ("law_enforcement", "law enforcement notified",
     re.compile(r"law enforcement|federal bureau of investigation|\bFBI\b", re.I)),
    ("material_language", "material impact language",
     re.compile(r"materially impact|material impact|has had a material|materially affect", re.I)),
    ("third_party", "third-party origin",
     re.compile(r"third[- ]party (?:vendor|service provider|provider|software|platform)|(?:a|its|our) (?:vendor|"
                r"service provider|supplier)(?:'s)? (?:systems|environment|platform)", re.I)),
)
_NOT_MATERIAL_RE = re.compile(r"(?:not|no longer) (?:currently )?(?:reasonably )?(?:expect(?:ed|s)?|believe[sd]?|"
                              r"likely)\W+(?:\w+\W+){0,6}?material", re.I)
_EXPECTED_MATERIAL_RE = re.compile(r"(?:is|are) reasonably likely to materially|has (?:had|determined)\W+(?:\w+\W+){0,4}?"
                                   r"material(?:ly)? impact|determined (?:that )?the incident (?:is|was) material", re.I)
_UNDETERMINED_RE = re.compile(r"(?:not yet|has not) (?:yet )?determined|unable to determine|too early to "
                              r"determine|continu(?:es|ing) to evaluate", re.I)


def parse_atom(body: bytes) -> list[dict]:
    out = []
    for entry in feedparser.parse(body).entries:
        match = _TITLE_RE.match(entry.get("title") or "")
        summary = re.sub(r"<[^>]+>", " ", entry.get("summary") or "")
        acc = _ACC_RE.search(summary)
        if not match or not acc:
            continue
        out.append({"form": match["form"], "company": match["company"].strip(), "cik": int(match["cik"]),
                    "accession": acc.group(1), "items": sorted(set(_ITEM_RE.findall(summary))),
                    "accepted": entry.get("updated"), "index_url": entry.get("link")})
    return out


def primary_document(index_html: bytes | str, form: str, base_url: str) -> str | None:
    soup = BeautifulSoup(index_html, "html.parser")
    for row in soup.select("table.tableFile tr"):
        cells = row.find_all("td")
        if len(cells) < 4:
            continue
        doc_type = cells[3].get_text(strip=True)
        anchor = cells[2].find("a")
        if anchor and doc_type.upper() == form.upper():
            href = anchor.get("href", "").replace("/ix?doc=", "")
            return urljoin(base_url, href)
    return None


def filing_text(html: bytes | str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style"]):
        tag.decompose()
    return _WS_RE.sub(" ", soup.get_text(" ")).replace("\xa0", " ").strip()


def item_section(text: str, item: str) -> str:
    starts = [m for m in _SECTION_RE.finditer(text) if m.group(1) == item]
    if not starts:
        return ""
    best = ""
    for start in starts:
        nxt = next((m for m in _SECTION_RE.finditer(text, start.end()) if m.group(1) != item), None)
        section = text[start.start():nxt.start() if nxt else len(text)]
        if len(section) > len(best):
            best = section
    return best


def severity(text: str) -> dict:
    features = {key: bool(rx.search(text)) for key, _, rx in FEATURES}
    if _NOT_MATERIAL_RE.search(text):
        features["materiality"] = "not expected"
    elif _UNDETERMINED_RE.search(text):
        features["materiality"] = "undetermined"
    elif _EXPECTED_MATERIAL_RE.search(text):
        features["materiality"] = "expected"
    else:
        features["materiality"] = None
    return features


def badges(features: dict, amendments: int = 0) -> list[str]:
    out = [label for key, label, _ in FEATURES if features.get(key)]
    materiality = features.get("materiality")
    if materiality == "not expected":
        out.append("not expected to be material")
    elif materiality == "expected":
        out.append("expected to be material")
    elif materiality == "undetermined":
        out.append("materiality undetermined")
    if amendments:
        out.append(f"amendment #{amendments}")
    return out


def cyber_keywords(section: str, keywords: list[str]) -> list[str]:
    low = section.lower()
    return [k for k in keywords if k.lower() in low]


class IncidentDesk:
    def __init__(self, app):
        self.app = app
        self.channel = "finance-incidents"
        self.keywords = list(((app.cfg.get("finance") or {}).get("incidents") or {}).get("keywords_8_01")
                             or DEFAULT_8_01_KEYWORDS)

    async def history_line(self) -> str | None:
        try:
            result = await self.app.study.aggregate("sec.8k.1_05", "car_0_5")
        except Exception:
            log.exception("history line failed")
            return None
        summary = result["main"]["summary"]
        if summary.n < 20:
            return None
        return (f"Historically, after 1.05 filings: median 5-day abnormal return {summary.median * 100:+.1f}% "
                f"(n={summary.n})")

    async def post_filing(self, event_id: int, *, original: dict | None = None) -> None:
        ev = await self.app.store.event_get(event_id)
        jump = None
        if original and original["source_refs"].get("message"):
            jump = self.app.poster.jump_url(*original["source_refs"]["message"])
        history = await self.history_line() if ev["type"] == "sec.8k.1_05" else None
        msg = await self.app.poster.send(self.channel, embed=render.incident_embed(ev, jump, history))
        if msg:
            await self.app.events.add_refs(event_id, {"message": [msg.channel.id, msg.id]})

    async def story_posted(self, sid: int, data: dict, msg, seed: bool) -> None:
        claim = data.get("claim")
        if not claim:
            return
        company = self.app.companies.resolve(claim["victim"])
        if company is None:
            return
        refs = {"story": sid, "url": data["url"]}
        if msg:
            refs["post"] = [msg.channel.id, msg.id]
        event_id, created = await self.app.events.record(
            "ransomware.claim.public", ticker=company.ticker, cik=company.cik, company=company.name,
            occurred_at=data.get("published") or parse_time_now(), dedup=f"story:{sid}",
            confidence=company.confidence, refs=refs,
            payload={"group": claim["group"], "victim": claim["victim"], "match": company.method})
        if created and not seed:
            await self._compact(event_id, f"**{claim['group']}** claims **{claim['victim']}**", refs.get("post"))

    async def story_merged(self, sid: int, data: dict, post: list | None) -> None:
        if len(data.get("also") or []) != 1:
            return
        _, labels = self.app.intel.analyze(data["title"], data.get("summary") or "", source=data["source"])
        if "breach" not in labels:
            return
        for company in self.app.companies.find_in_text(data["title"]):
            refs = {"story": sid, "url": data["url"], **({"post": post} if post else {})}
            event_id, created = await self.app.events.record(
                "breach.news.public", ticker=company.ticker, cik=company.cik, company=company.name,
                occurred_at=data.get("published") or parse_time_now(), dedup=f"story:{sid}",
                confidence=company.confidence, refs=refs,
                payload={"title": data["title"], "outlets": 1 + len(data.get("also") or []), "match": company.method})
            if created:
                await self._compact(event_id, data["title"], post)

    async def _compact(self, event_id: int, text: str, post: list | None) -> None:
        ev = await self.app.store.event_get(event_id)
        jump = self.app.poster.jump_url(*post) if post else None
        msg = await self.app.poster.send(self.channel, embed=render.compact_incident_embed(ev, text, jump))
        if msg:
            await self.app.events.add_refs(event_id, {"message": [msg.channel.id, msg.id]})


def parse_time_now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()
