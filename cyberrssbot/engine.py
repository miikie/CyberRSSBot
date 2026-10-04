from __future__ import annotations

import logging
import re
import time
from datetime import datetime, timezone

from . import render
from .dedup import StoryIndex, fingerprint
from .msrc import kb_url
from .util import parse_claim, parse_time

log = logging.getLogger(__name__)

SEVERITY_ESTIMATE = {"CRITICAL": 9.0, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.0}
SCORE_PRIORITY = {"nvd": 2, "ghsa": 1}
LIST_FIELDS = ("aliases", "cwe", "packages")
FIRST_WINS = ("title", "description", "vendor", "product", "cna", "published")


def merge_vuln(old: dict | None, new: dict) -> tuple[dict, set[str]]:
    if old is None:
        merged = {"refs": {}, "news": [], "aliases": [], "cwe": [], "packages": []}
        merged.update({k: v for k, v in new.items() if v is not None})
        merged["aliases"] = sorted(set(merged["aliases"]) - {merged["id"]})
        return merged, {"new"}

    m = dict(old)
    changes: set[str] = set()

    for field in FIRST_WINS:
        if new.get(field) and not m.get(field):
            m[field] = new[field]
            changes.add(field)

    if new.get("status") and new["status"] != m.get("status"):
        m["status"] = new["status"]
        if new["status"] == "Rejected":
            changes.add("rejected")

    new_prio = SCORE_PRIORITY.get(new.get("score_source"), 0)
    old_prio = SCORE_PRIORITY.get(m.get("score_source"), 0)
    has_score = new.get("cvss") is not None or bool(new.get("severity"))
    takes_over = (new_prio > old_prio
                  or (new_prio == old_prio and new.get("cvss") is not None)
                  or (m.get("cvss") is None and not m.get("severity")))
    if has_score and takes_over:
        before = (m.get("cvss"), m.get("severity"))
        for field in ("cvss", "cvss_version", "severity", "score_source"):
            m[field] = new.get(field)
        if (m.get("cvss"), m.get("severity")) != before:
            changes.add("score")

    for field in LIST_FIELDS:
        incoming = set(new.get(field) or [])
        if field == "aliases":
            incoming.add(new["id"])
        current = sorted(m.get(field) or [])
        merged_list = sorted((set(current) | incoming) - ({m["id"]} if field == "aliases" else set()))
        if merged_list != current:
            m[field] = merged_list
            changes.add(field)

    refs = dict(m.get("refs") or {})
    for name, url in (new.get("refs") or {}).items():
        if name not in refs and url:
            refs[name] = url
            changes.add("refs")
    m["refs"] = refs

    news = list(m.get("news") or [])
    known = {n["url"] for n in news}
    for item in new.get("news") or []:
        if item["url"] not in known:
            news.append(item)
            known.add(item["url"])
            changes.add("news")
    m["news"] = news[:10]

    if new.get("kev") and not m.get("kev"):
        m["kev"] = new["kev"]
        changes.add("kev")

    if new.get("epss") is not None:
        if m.get("epss") is None or abs(m["epss"] - new["epss"]) >= 0.01:
            changes.add("epss")
        m["epss"] = new["epss"]
        m["epss_pct"] = new.get("epss_pct")

    return m, changes


class VulnEngine:
    def __init__(self, app):
        self.app = app
        f = app.cfg["filters"]["vulns"]
        self.f = f
        terms = [t.lower() for t in f.get("watchlist") or []]
        self.watch_re = re.compile(r"\b(" + "|".join(map(re.escape, terms)) + r")\b") if terms else None
        self.mute_cnas = {c.lower() for c in f.get("mute_cnas") or []}
        self.mute_patterns = [p.lower() for p in f.get("mute_patterns") or []]

    def watched(self, d: dict) -> bool:
        if not self.watch_re:
            return False
        hay = " ".join(str(d.get(k) or "") for k in ("vendor", "product", "cna", "title", "description"))
        hay += " " + " ".join(d.get("packages") or [])
        return bool(self.watch_re.search(hay.lower().replace("_", " ")))

    def muted(self, d: dict) -> bool:
        if (d.get("cna") or "").lower() in self.mute_cnas:
            return True
        hay = f"{d.get('title') or ''} {d.get('description') or ''}".lower()
        return any(p in hay for p in self.mute_patterns)

    def should_post(self, d: dict) -> bool:
        if d.get("status") == "Rejected":
            return False
        if d.get("kev"):
            return True
        published = parse_time(d.get("published"))
        if published and (datetime.now(timezone.utc) - published).days > self.f["max_age_days"]:
            return False
        watched = self.watched(d)
        if self.muted(d) and not watched:
            return False
        score = d.get("cvss")
        if score is None:
            score = SEVERITY_ESTIMATE.get((d.get("severity") or "").upper())
        if score is not None and score >= self.f["min_cvss"]:
            return True
        if d.get("epss") is not None and d["epss"] >= self.f["min_epss"]:
            return True
        return bool(watched and score is not None and score >= self.f["watch_min_cvss"])

    async def ingest(self, partial: dict, *, seed: bool = False) -> str:
        store = self.app.store
        partial = dict(partial)
        partial["id"] = partial["id"].upper()
        partial["aliases"] = [a.upper() for a in partial.get("aliases") or []]
        vid = await store.vuln_resolve([partial["id"], *partial["aliases"]]) or partial["id"]

        row = await store.vuln_get(vid)
        merged, changes = merge_vuln(row["data"] if row else None, partial)
        merged["id"] = vid
        merged["aliases"] = [a for a in merged.get("aliases", []) if a != vid]
        if row is None:
            fixed = {f"Fixed in KB{kb}": kb_url(kb) for kb in await store.ms_kbs_for_cves([vid, *merged["aliases"]])}
            if fixed:
                merged["refs"] = {**(merged.get("refs") or {}), **fixed}
        if merged.get("kev") and ("kev" in changes or row is None):
            merged["kev"] = {**merged["kev"], "seen": int(time.time())}
        await store.vuln_put(vid, merged, [vid, *merged["aliases"]])
        if (merged.get("kev") or (merged.get("cvss") or 0) >= 9) and changes:
            from .backfill import vuln_events
            await vuln_events(self.app, merged)

        if row is None:
            if seed:
                await store.vuln_set_post(vid, -1)
                return vid
            posted = 0
        else:
            posted = row["posted"]

        if posted == 0:
            if not seed and self.should_post(merged):
                await self._post(vid, merged)
        elif posted == 1 and changes - {"new"}:
            await store.vuln_mark_dirty(vid)
            if "kev" in changes and not seed and row.get("message_id"):
                await self._escalate(merged, row)
        return vid

    async def _post(self, vid: str, d: dict) -> None:
        key = "kev" if d.get("kev") else "vulns"
        intel = self.app.intel
        if key == "vulns" and intel.routes:
            key = intel.route(intel.analyze(d.get("title") or "", d.get("description") or "", kind="vuln",
                                            vuln=d)[1], key, self.app.poster.usable)
        msg = await self.app.poster.send(key, embed=render.vuln_embed(d), ping_kev=bool(d.get("kev")))
        if msg:
            await self.app.store.vuln_set_post(vid, 1, msg.channel.id, msg.id)

    async def _escalate(self, d: dict, row: dict) -> None:
        jump = self.app.poster.jump_url(row["channel_id"], row["message_id"])
        await self.app.poster.send("kev", embed=render.kev_escalation_embed(d, jump), ping_kev=True)

    async def attach_news(self, cve: str, item: dict) -> None:
        vid = await self.app.store.vuln_resolve([cve])
        if vid:
            await self.ingest({"id": vid, "news": [{"title": item["title"], "url": item["url"],
                                                    "source": item["source"]}]})

    async def is_posted(self, cve: str) -> bool:
        vid = await self.app.store.vuln_resolve([cve])
        row = await self.app.store.vuln_get(vid) if vid else None
        return bool(row and row["posted"] == 1)


class StoryEngine:
    def __init__(self, app):
        self.app = app
        d = app.cfg["dedup"]
        self.window = float(d["story_window_hours"]) * 3600
        self.fold = bool(d.get("fold_cve_news"))
        self.index = StoryIndex(self.window, float(d["title_threshold"]), float(d["cve_title_threshold"]))

    async def load(self) -> None:
        for sid, ts, tokens, cves in await self.app.store.stories_recent(time.time() - self.window):
            self.index.add(sid, ts, tokens, cves)

    async def ingest(self, item: dict, *, seed: bool, channel_key: str, cluster: bool = True) -> None:
        store = self.app.store
        tokens, cves = fingerprint(item["title"], item.get("summary", ""))
        now = time.time()

        sid = self.index.find(tokens, cves, now) if cluster else None
        if sid is not None:
            row = await store.story_get(sid)
            if row:
                data = row["data"]
                outlets = {data["source"], *(a["source"] for a in data["also"])}
                if item["source"] not in outlets:
                    data["also"].append({"source": item["source"], "url": item["url"]})
                    await store.story_update(sid, data=data, dirty=1)
                    post = [row["channel_id"], row["message_id"]] if row.get("message_id") else None
                    await self.app.incidents.story_merged(sid, data, post)
                return

        if self.fold and cves:
            all_known = True
            for cve in cves:
                if not await self.app.vulns.is_posted(cve):
                    all_known = False
                    break
            if all_known:
                for cve in cves:
                    await self.app.vulns.attach_news(cve, item)
                return

        if not seed and self.app.intel.routes:
            _, labels = self.app.intel.analyze(item["title"], item.get("summary", ""), source=item["source"])
            channel_key = self.app.intel.route(labels, channel_key, self.app.poster.usable)
        data = {
            "title": item["title"], "url": item["url"], "source": item["source"],
            "summary": item.get("summary", ""), "published": item.get("published"),
            "cves": sorted(cves), "also": [], "channel": channel_key,
        }
        claim = parse_claim(item["title"])
        if claim:
            data["claim"] = claim
        sid = await store.story_insert(now, tokens, cves, data)
        if cluster:
            self.index.add(sid, now, tokens, cves)
        for cve in cves:
            await self.app.vulns.attach_news(cve, item)
        if seed:
            await self.app.incidents.story_posted(sid, data, None, True)
            return
        msg = await self.app.poster.send(channel_key, embed=render.story_embed(data))
        if msg:
            await store.story_update(sid, channel_id=msg.channel.id, message_id=msg.id)
        await self.app.incidents.story_posted(sid, data, msg, False)
