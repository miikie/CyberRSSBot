from __future__ import annotations

import asyncio
import hashlib
import html
import logging
import re
import statistics
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from . import msrc, render
from .classify import score
from .dedup import CVE_RE
from .extract import extract
from .util import parse_time, primary_id

DEFAULT_SECTIONS = [
    {"key": "exploited", "title": "Exploited in the wild", "labels": ["exploited"]},
    {"key": "vulnerabilities", "title": "Vulnerabilities & patches", "labels": ["vulnerability"]},
    {"key": "breaches", "title": "Breaches & ransomware", "labels": ["breach", "ransomware"]},
    {"key": "actors", "title": "Threat actors", "labels": ["apt"]},
    {"key": "malware", "title": "Malware", "labels": ["malware"]},
    {"key": "supply-chain", "title": "Supply chain", "labels": ["supply-chain"]},
    {"key": "law-enforcement", "title": "Law enforcement", "labels": ["law-enforcement"]},
    {"key": "policy", "title": "Policy & law", "labels": ["policy-law"]},
    {"key": "markets", "title": "Markets", "labels": ["finance"]},
]
DEFAULT_LABEL_PRIORITY = ["exploited", "law-enforcement", "policy-law", "supply-chain", "apt", "malware",
                          "ransomware", "breach", "vulnerability", "finance"]
DEFAULT_EDITIONS = [
    {"name": "6h", "hours": 6, "at_utc": ["00:00", "06:00", "12:00", "18:00"]},
    {"name": "daily", "hours": 24, "at_utc": ["06:00"]},
]
KEV_TEMPLATES = (
    "CISA added {count} to the Known Exploited Vulnerabilities catalog in this window: {items}.",
    "{count} joined CISA's Known Exploited Vulnerabilities catalog: {items}.",
    "New in CISA KEV this window, {count}: {items}.",
)
WINDOWS_TEMPLATES = (
    "Microsoft shipped {updates} fixing **{cves}** CVEs, {critical} rated Critical and {exploited} exploited: {items}.",
    "Windows servicing this window: {updates} covering **{cves}** CVEs ({critical} Critical, {exploited} exploited). "
    "Cards: {items}.",
)
MOVER_TEMPLATES = (
    "Biggest movers on the watchlist: {up} and {down}.",
    "Watchlist movers: {up} gained the most; {down} fell the most.",
    "On the watchlist, {up} led and {down} lagged.",
)
SEPARATORS = (" - ", " | ", " – ", " — ", " :: ", " » ")
KEEP_UPPER = {"FBI", "CISA", "NSA", "DOJ", "SEC", "US", "UK", "EU", "RCE", "VPN", "API", "AI", "IT", "OT", "ICS",
              "SQL", "XSS", "SSO", "MFA", "DNS", "KEV", "NVD", "APT", "CEO", "CISO", "IOT", "SaaS", "DDoS", "PoC"}
ABBREVIATIONS = {"mr", "mrs", "ms", "dr", "inc", "ltd", "corp", "co", "vs", "e.g", "i.e", "u.s", "u.k", "no", "jr",
                 "sr", "st", "gen", "gov", "sen", "rep", "etc", "approx", "est", "fig", "u.s.a", "e.u"}
GAIN, LOSS = "+", "−"

_WS_RE = re.compile(r"\s+")
_SENTENCE_END_RE = re.compile(r"[.!?]+[\"”’')\]]*\s+")
_DOMAIN_RE = re.compile(r"^[\w-]+(\.[\w-]+)*\.(com|net|org|io|co|uk|news|media)$", re.IGNORECASE)
_ALNUM_RE = re.compile(r"[^a-z0-9]+")
_CLAUSE_RE = re.compile(r"[,;:(]|\.\s|\s[-–—]\s")
_LEAD_SYMBOL_RE = re.compile(r"^[^\w\"'“‘(\[$€£#@]+")
_DATED_RE = re.compile(r"\d{4}-\d{2}-\d{2}")
_MD_RE = re.compile(r"([\\*_`~|])")

log = logging.getLogger(__name__)


@dataclass
class Block:
    title: str | None
    chunks: list[str]


@dataclass
class Digest:
    run_id: str
    edition: str
    start: datetime
    end: datetime
    messages: list[str] = field(default_factory=list)
    stats: dict = field(default_factory=dict)

    def window(self) -> str:
        return window_text(self.start, self.end)

    def text(self) -> str:
        return "\n\n=====\n\n".join(self.messages) + "\n"


def run_id(end: datetime, hours: float) -> str:
    return f"{end:%Y%m%dT%H%MZ}-{hours:g}h"


def window_text(start: datetime, end: datetime) -> str:
    if start.date() == end.date():
        return f"{start:%Y-%m-%d %H:%M}–{end:%H:%M} UTC"
    return f"{start:%Y-%m-%d %H:%M}–{end:%Y-%m-%d %H:%M} UTC"


def pick(templates: tuple[str, ...], run: str, case: str) -> str:
    digest = hashlib.sha256(f"{run}|{case}".encode()).hexdigest()
    return templates[int(digest, 16) % len(templates)]


def md(text: str) -> str:
    return _MD_RE.sub(r"\\\1", text.replace("[", "(").replace("]", ")"))


def link(text: str, url: str | None) -> str:
    if not url:
        return text
    return f"[{text}]({url.strip().replace(' ', '%20').replace('(', '%28').replace(')', '%29')})"


def _key(value: str) -> str:
    return _ALNUM_RE.sub("", value.lower())


def clean_headline(title: str, outlets: list[str], kb=None) -> str:
    text = _LEAD_SYMBOL_RE.sub("", _WS_RE.sub(" ", html.unescape(title or "")).strip())
    known = {_key(o) for o in outlets}
    changed = True
    while changed:
        changed = False
        for sep in SEPARATORS:
            head, found, tail = text.rpartition(sep)
            if found and head and (_key(tail) in known or _DOMAIN_RE.match(tail.strip())):
                text, changed = head.strip(), True
    letters = [c for c in text if c.isalpha()]
    if len(letters) >= 8 and sum(c.isupper() for c in letters) / len(letters) > 0.7:
        words = []
        for word in text.split(" "):
            bare = word.strip(".,:;!?()\"'")
            canonical = next((k for k in KEEP_UPPER if k.upper() == bare.upper()), None)
            entity = kb.lookup(bare) if kb and bare else []
            if CVE_RE.fullmatch(bare):
                words.append(word.upper())
            elif canonical:
                words.append(word.replace(bare, canonical))
            elif entity:
                name = next((n for n in entity[0].names() if n.lower() == bare.lower()), bare.capitalize())
                words.append(word.replace(bare, name))
            else:
                words.append(word.lower())
        text = " ".join(words)
        text = text[:1].upper() + text[1:]
    return text.rstrip(" .")


def split_sentences(text: str) -> list[str]:
    text = _WS_RE.sub(" ", text or "").strip()
    out, start = [], 0
    for match in _SENTENCE_END_RE.finditer(text):
        words = text[start:match.start()].split()
        last = words[-1].lower().rstrip(".") if words else ""
        following = text[match.end():match.end() + 1]
        if text[match.start()] == "." and (
                last in ABBREVIATIONS or len(last) == 1
                or not (following.isupper() or following.isdigit() or following in "\"“'‘([")):
            continue
        out.append(text[start:match.start() + len(match.group().rstrip())].strip())
        start = match.end()
    if text[start:].strip():
        out.append(text[start:].strip())
    return out


def best_sentence(summary: str, title: str, kb, max_words: int = 40) -> str | None:
    headline = _key(title)
    best = None
    for index, sentence in enumerate(split_sentences(summary)):
        words = sentence.split()
        if len(words) < 6 or sentence.startswith("The post ") or sentence.rstrip("\"”’')]").endswith(("…", "...")):
            continue
        if "•" in sentence or _DATED_RE.match(sentence):
            continue
        key = _key(sentence)
        if key and (key == headline or headline.startswith(key) or key.startswith(headline) and len(headline) > 20):
            continue
        hits = len(extract(sentence, kb).spans)
        rank = (hits / len(words), -index)
        if best is None or rank > best[0]:
            best = (rank, sentence)
    if best is None:
        return None
    words = best[1].split()
    return " ".join(words[:max_words]).rstrip(",;:") + "…" if len(words) > max_words else best[1]


def first_clause(text: str, max_words: int = 12) -> str:
    text = _WS_RE.sub(" ", text or "").strip()
    clause = _CLAUSE_RE.split(text, maxsplit=1)[0].strip().rstrip(".")
    words = clause.split()
    return " ".join(words[:max_words]) + "…" if len(words) > max_words else clause


def emphasize(text: str, kb) -> str:
    out, pos = [], 0
    for start, end in extract(text, kb).spans:
        out.append(md(text[pos:start]))
        out.append(f"**{md(text[start:end])}**")
        pos = end
    out.append(md(text[pos:]))
    return "".join(out)


def paginate(blocks: list[Block], limit: int) -> list[str]:
    def render_block(block: Block, chunks: list[str], continued: bool = False) -> str:
        head = f"**{block.title}{' (continued)' if continued else ''}**\n" if block.title else ""
        return head + "\n\n".join(chunks)

    messages: list[str] = []
    current = ""

    def flush() -> None:
        nonlocal current
        if current:
            messages.append(current)
        current = ""

    for block in blocks:
        chunks = [c if len(c) <= limit - 80 else c[:limit - 81].rstrip() + "…" for c in block.chunks]
        whole = render_block(block, chunks)
        if len(current) + len(whole) + 2 <= limit:
            current = f"{current}\n\n{whole}" if current else whole
            continue
        if len(whole) <= limit:
            flush()
            current = whole
            continue
        flush()
        part: list[str] = []
        continued = False
        for chunk in chunks:
            if part and len(render_block(block, part + [chunk], continued)) > limit:
                messages.append(render_block(block, part, continued))
                part, continued = [], True
            part.append(chunk)
        current = render_block(block, part, continued)
    flush()
    return messages


def _plural(count: int, noun: str, plural: str | None = None) -> str:
    return f"**{count}** {noun if count == 1 else plural or noun + 's'}"


def _listing(parts: list[str], limit: int) -> str:
    shown = parts[:limit]
    if len(parts) > limit:
        shown.append(f"+{len(parts) - limit} more")
    return ", ".join(shown)


def compose(inputs: dict, cfg: dict, intel, start: datetime, end: datetime, edition: str) -> Digest:
    hours = (end - start).total_seconds() / 3600
    out = Digest(run_id(end, hours), edition, start, end)
    kb = intel.kb
    sections = cfg.get("sections") or DEFAULT_SECTIONS
    top_n = int(cfg.get("top_n", 5))
    max_words = int(cfg.get("max_words", 40))
    min_score = float(cfg.get("min_score", 0))
    grace = timedelta(hours=float(cfg.get("late_grace_hours", 6)))
    start_ts, end_ts = start.timestamp(), end.timestamp()
    stats = {"raw": 0, "clustered": 0, "excluded": 0, "unclassified": 0, "below_cut": 0}

    def age(when: datetime) -> float:
        return (end - when).total_seconds() / 3600

    def dated(published: str | None, seen: float) -> datetime | None:
        when = parse_time(published)
        if when is None:
            return datetime.fromtimestamp(seen, timezone.utc)
        return None if when < start - grace or when > end else when

    def affected(d: dict) -> str:
        parts = []
        for value in (d.get("vendor"), d.get("product")):
            value = (value or "").replace("_", " ").strip()
            known = kb.lookup(value) if value else []
            if value:
                parts.append(next((n for e in known for n in e.names() if n.lower() == value.lower()),
                                  value.title()))
        return " ".join(parts)

    items = []
    for row in sorted(inputs.get("stories") or [], key=lambda r: r["id"]):
        d = row["data"]
        stats["raw"] += 1 + len(d.get("also") or [])
        stats["clustered"] += 1
        when = dated(d.get("published"), row["ts"])
        if when is None:
            stats["excluded"] += 1
            continue
        ex, labels = intel.analyze(d["title"], d.get("summary") or "", source=d["source"])
        text = f"{d['title']} {d.get('summary') or ''}"
        items.append({
            "kind": "story", "sort": f"s{row['id']:012d}", "labels": labels, "title": d["title"], "url": d["url"],
            "source": d["source"], "summary": d.get("summary") or "", "also": d.get("also") or [], "tags": [],
            "score": score(ex, weights=intel.weights, outlets=len(d.get("also") or []), watched=intel.watched(text),
                           primary=d["source"] in intel.primary, age_hours=age(when)),
        })

    kev_new = []
    for row in sorted(inputs.get("vulns") or [], key=lambda r: r["vid"]):
        d = row["data"]
        if row.get("posted") == -1 or d.get("status") == "Rejected":
            continue
        kev = d.get("kev") or {}
        kev_in_window = bool(kev) and start_ts <= float(kev.get("seen") or 0) < end_ts
        fresh = start_ts <= row["first_seen"] < end_ts
        if kev_in_window:
            kev_new.append(d)
        if not (kev_in_window or (fresh and row.get("posted") == 1)):
            continue
        stats["raw"] += 1
        stats["clustered"] += 1
        pid = primary_id(d)
        refs = d.get("refs") or {}
        outlet = "NVD" if "NVD" in refs else next(iter(refs), "the CVE record")
        label = d.get("title") or affected(d) \
            or next((kb.cwe[c.upper()] for c in d.get("cwe") or [] if c.upper() in kb.cwe), "") \
            or first_clause(d.get("description") or "")
        ex, labels = intel.analyze(f"{pid} {label}", d.get("description") or "", kind="vuln", vuln=d)
        tags = []
        if d.get("cvss") is not None:
            tags.append(f"CVSS {float(d['cvss']):.1f}")
        if kev:
            tags.append("KEV")
        news = d.get("news") or []
        when = parse_time(d.get("published")) or datetime.fromtimestamp(row["first_seen"], timezone.utc)
        items.append({
            "kind": "vuln", "sort": f"v{pid}", "labels": labels, "title": f"{pid} — {label}" if label else pid,
            "url": refs.get("NVD") or next(iter(refs.values()), None), "source": outlet,
            "summary": d.get("description") or "", "tags": tags,
            "also": [{"source": n["source"], "url": n["url"]} for n in news],
            "score": score(ex, weights=intel.weights, outlets=len(news), kev=bool(kev), cvss=d.get("cvss"),
                           watched=intel.watched(f"{label} {d.get('description') or ''}"), primary=True,
                           age_hours=max(0.0, min(age(when), hours))),
        })

    for row in sorted(inputs.get("finance") or [], key=lambda r: r["id"]):
        d = row["data"]
        stats["raw"] += 1 + len(d.get("also") or [])
        stats["clustered"] += 1
        when = dated(d.get("published"), row["ts"])
        if when is None:
            stats["excluded"] += 1
            continue
        ex, labels = intel.analyze(d["title"], d.get("summary") or "", kind="finance")
        items.append({
            "kind": "finance", "sort": f"f{row['id']:012d}", "labels": labels,
            "title": f"{'/'.join(d.get('tickers') or [])}: {d['title']}" if d.get("tickers") else d["title"],
            "url": d["url"], "source": d["source"], "summary": d.get("summary") or "",
            "also": d.get("also") or [], "tags": [],
            "score": score(ex, weights=intel.weights, outlets=len(d.get("also") or []),
                           primary=d.get("kind") == "filing", age_hours=age(when)),
        })

    outlets = intel.outlets

    def render_item(item: dict) -> str:
        headline = clean_headline(item["title"], outlets, kb)
        head = f"▸ **{link(md(headline), item['url'])}**"
        if item["tags"]:
            head += " · " + " · ".join(item["tags"])
        sentence = None if item["kind"] == "story" and item["source"] in intel.no_quote \
            else best_sentence(item["summary"], headline, kb, max_words)
        lines = [head, f"“{emphasize(sentence, kb)}” (per {md(item['source'])})"] if sentence \
            else [f"{head} (per {md(item['source'])})"]
        seen, also = {item["source"]}, []
        for other in item["also"]:
            if other["source"] not in seen:
                seen.add(other["source"])
                also.append(link(md(other["source"]), other["url"]))
        if also:
            lines.append("Also covered by " + " · ".join(also[:6]))
        return "\n".join(lines)

    priority = cfg.get("label_priority") or DEFAULT_LABEL_PRIORITY
    section_of = {}
    for section in sections:
        for label in section.get("labels") or []:
            section_of.setdefault(label, section["key"])

    buckets: dict[str, list[dict]] = {s["key"]: [] for s in sections}
    classified, unclassified = [], []
    for item in items:
        ordered = [l for l in priority if l in item["labels"]] + [l for l in item["labels"] if l not in priority]
        if item["kind"] == "story":
            ordered = [l for l in intel.source_labels.get(item["source"], ()) if l in item["labels"]] + ordered
        if item["kind"] == "finance":
            ordered = ["finance"]
        home = next((section_of[l] for l in ordered if l in section_of), None)
        if home is None:
            unclassified.append(item)
            continue
        classified.append(item["score"])
        if item["score"] < min_score:
            stats["below_cut"] += 1
        else:
            buckets[home].append(item)

    other = {"enabled": True, "title": "Other notable", "top_n": 3, **(cfg.get("other") or {})}
    notable = []
    if other["enabled"] and classified:
        median = statistics.median(classified)
        notable = sorted((i for i in unclassified if i["kind"] == "story" and i["score"] > median
                          and i["score"] >= min_score), key=lambda i: (-i["score"], i["sort"]))[:int(other["top_n"])]
    stats["unclassified"] = len(unclassified) - len(notable)

    paragraphs: dict[str, list[str]] = {}
    if kev_new:
        entries = []
        for d in sorted(kev_new, key=primary_id):
            pid = primary_id(d)
            what = affected(d)
            entries.append(link(pid, (d.get("refs") or {}).get("CISA KEV") or (d.get("refs") or {}).get("NVD"))
                           + (f" ({md(what)})" if what else ""))
        text = pick(KEV_TEMPLATES, out.run_id, "kev").format(
            count=_plural(len(kev_new), "vulnerability", "vulnerabilities"), items=_listing(entries, 6))
        paragraphs["exploited"] = [text[:1].upper() + text[1:]]
    windows = inputs.get("windows")
    if windows and windows.get("updates"):
        cards = [link(f"KB{u['kb']}", u.get("url") or msrc.kb_url(u["kb"])) for u in windows["updates"]]
        paragraphs["vulnerabilities"] = [pick(WINDOWS_TEMPLATES, out.run_id, "windows").format(
            updates=_plural(len(cards), "Windows security update"), cves=windows["cves"],
            critical=windows["critical"], exploited=windows["exploited"], items=_listing(cards, 10))]
    quotes = sorted((q for q in inputs.get("quotes") or [] if start_ts <= q["ts"] < end_ts and q.get("dp") is not None),
                    key=lambda q: (-float(q["dp"]), q["symbol"]))
    if len(quotes) >= 2 and float(quotes[0]["dp"]) > 0 > float(quotes[-1]["dp"]):
        def mover(q):
            dp = float(q["dp"])
            return f"**{q['symbol']}** ({md(q['name'])}) {GAIN if dp >= 0 else LOSS}{abs(dp):.2f}%"
        paragraphs["markets"] = [pick(MOVER_TEMPLATES, out.run_id, "movers").format(
            up=mover(quotes[0]), down=mover(quotes[-1]))]

    blocks = [Block(None, [f"Window: {out.window()} · Run `{out.run_id}`"])]
    quiet, used = [], {}
    for section in sections:
        ranked = sorted(buckets[section["key"]], key=lambda i: (-i["score"], i["sort"]))
        limit = int(section.get("top", top_n))
        stats["below_cut"] += max(0, len(ranked) - limit)
        chunks = paragraphs.get(section["key"], []) + [render_item(i) for i in ranked[:limit]]
        if chunks:
            blocks.append(Block(section["title"], chunks))
            used[section["key"]] = min(len(ranked), limit)
        else:
            quiet.append(section["title"])
    if notable:
        blocks.append(Block(other["title"], [render_item(i) for i in notable]))
        used["other"] = len(notable)

    sources = inputs.get("sources") or []
    failed = [s for s in sources if (s.get("fails") or 0) > 0]
    checked = [s for s in sources if (s.get("last_ok") or 0) >= start_ts and not (s.get("fails") or 0)]
    idle = len(sources) - len(failed) - len(checked)
    lines = []
    if sources and not checked:
        lines.append(f"Sources: none of the {len(sources)} configured sources could be checked in this window, "
                     "so this digest says nothing about what happened.")
    else:
        line = f"Sources: {len(checked)} of {len(sources)} checked"
        if idle:
            line += f", {idle} not polled in this window"
        lines.append(line + ".")
    if failed:
        reasons = [f"`{s['id']}` ({md(str(s.get('last_err') or 'unknown error'))[:80]})"
                   for s in sorted(failed, key=lambda s: s["id"])]
        lines.append(f"Failed ({len(failed)}): {_listing(reasons, 8)}.")
    for note in inputs.get("kb_failed") or []:
        lines.append(f"Reference data: {md(note)[:160]}.")
    lines.append(f"Items: {stats['raw']} raw → {stats['clustered']} clustered stories and records; "
                 f"{stats['excluded']} dated outside the window and excluded.")
    held = stats["unclassified"] + stats["below_cut"]
    if held:
        lines.append(f"Not shown: {stats['unclassified']} matched no section, {stats['below_cut']} ranked below "
                     "the cut.")
    if quiet:
        lines.append("No qualifying items from checked sources: " + ", ".join(quiet) + ".")
    lines.append("Rule-based and automated. Quoted sentences are taken verbatim from the linked sources.")
    blocks.append(Block("Coverage & limitations", ["\n".join(lines)]))

    out.messages = paginate(blocks, int(cfg.get("max_message_chars", 3800)))
    out.stats = {**stats, "sections": used, "quiet": quiet, "sources": len(sources), "checked": len(checked),
                 "failed": [{"id": s["id"], "error": s.get("last_err")} for s in sorted(failed, key=lambda s: s["id"])],
                 "items": sum(used.values()), "messages": len(out.messages)}
    return out


def schedule(editions: list[dict], now: datetime) -> list[tuple[dict, datetime]]:
    due = []
    for edition in editions:
        best = None
        for stamp in edition.get("at_utc") or []:
            hour, _, minute = str(stamp).partition(":")
            moment = now.replace(hour=int(hour), minute=int(minute or 0), second=0, microsecond=0)
            if moment > now:
                moment -= timedelta(days=1)
            if best is None or moment > best:
                best = moment
        if best is not None:
            due.append((edition, best))
    return due


class DigestRunner:
    def __init__(self, app):
        self.app = app
        self.cfg = app.cfg.get("digest") or {}
        self.channel = self.cfg.get("channel") or "digest"

    async def collect(self, start: datetime, end: datetime) -> dict:
        app, store = self.app, self.app.store
        start_ts, end_ts = start.timestamp(), end.timestamp()
        states = {row["id"]: row for row in await store.all_sources()}
        kbs = await store.ms_kbs_between(start_ts, end_ts)
        windows = None
        if kbs:
            cves: dict[str, dict] = {}
            for row in kbs:
                cves.update(row["data"]["cves"])
            windows = {
                "updates": [{"kb": r["kb"], "url": app.poster.jump_url(r["channel_id"], r["message_id"])}
                            for r in kbs],
                "cves": len(cves),
                "critical": sum(1 for c in cves.values() if c["severity"] == "Critical"),
                "exploited": sum(1 for c in cves.values() if c["exploited"]),
            }
        watch = app.finance.watch
        return {
            "stories": await store.stories_between(start_ts, end_ts),
            "vulns": await store.vulns_window(start_ts, end_ts),
            "finance": await store.fin_between(start_ts, end_ts),
            "quotes": [{"symbol": sym, "name": watch.name(sym), "dp": q.get("dp"), "ts": ts}
                       for sym, q, ts in await store.quotes_all() if sym in watch.companies],
            "windows": windows,
            "sources": [{"id": s.id, "name": s.name, **{k: states.get(s.id, {}).get(k)
                                                        for k in ("last_ok", "fails", "last_err")}}
                        for s in app.sources],
            "kb_failed": app.kb.failed(),
        }

    async def build(self, hours: float, end: datetime, edition: str) -> Digest:
        end = end.astimezone(timezone.utc).replace(second=0, microsecond=0)
        start = end - timedelta(hours=hours)
        inputs = await self.collect(start, end)
        return await asyncio.to_thread(compose, inputs, self.cfg, self.app.intel, start, end, edition)

    async def post(self, digest: Digest) -> int:
        poster = self.app.poster
        posted = 0
        for index, message in enumerate(digest.messages):
            embed = render.digest_embed(digest, message, index)
            if await poster.send(self.channel, embed=embed, fallback=False):
                posted += 1
        if posted:
            await self.app.store.mark_seen(["digest:" + digest.run_id], "digest")
        else:
            log.warning("digest %s was not posted: the '%s' channel is not set or failed the channel check",
                        digest.run_id, self.channel)
        await poster.send("log", embed=render.digest_summary_embed(digest, posted), fallback=False)
        return posted

    def upcoming(self, now: datetime) -> list[tuple[str, float, datetime]]:
        out = []
        for edition in self.cfg.get("editions") or DEFAULT_EDITIONS:
            times = []
            for stamp in edition.get("at_utc") or []:
                hour, _, minute = str(stamp).partition(":")
                moment = now.replace(hour=int(hour), minute=int(minute or 0), second=0, microsecond=0)
                times.append(moment if moment > now else moment + timedelta(days=1))
            if times:
                hours = float(edition.get("hours", 6))
                out.append((str(edition.get("name") or f"{hours:g}h"), hours, min(times)))
        return sorted(out, key=lambda item: (item[2], item[0]))

    async def loop(self) -> None:
        store = self.app.store
        grace = float(self.cfg.get("catch_up_minutes", 90)) * 60
        while True:
            try:
                now = datetime.now(timezone.utc)
                for edition, moment in schedule(self.cfg.get("editions") or DEFAULT_EDITIONS, now):
                    hours = float(edition.get("hours", 6))
                    key = "digest:" + run_id(moment, hours)
                    if (now - moment).total_seconds() > grace or await store.seen_any([key]):
                        continue
                    await store.mark_seen([key], "digest")
                    digest = await self.build(hours, moment, str(edition.get("name") or f"{hours:g}h"))
                    if digest.stats["items"] or self.cfg.get("post_empty", True):
                        await self.post(digest)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("digest loop error")
            await asyncio.sleep(60 - time.time() % 60 + 5)
