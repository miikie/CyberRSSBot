from __future__ import annotations

import json
import logging
import re
import time
from datetime import datetime, timedelta, timezone

from ..http import FetchError
from ..util import parse_time, primary_id
from .base import Source

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_MIRROR = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
GHSA_URL = "https://api.github.com/advisories"
EPSS_URL = "https://api.first.org/data/v1/epss"
JSON_ACCEPT = {"Accept": "application/json"}

log = logging.getLogger(__name__)


def _cna(source_identifier: str | None) -> str | None:
    if not source_identifier or "@" not in source_identifier:
        return None
    labels = source_identifier.split("@", 1)[1].lower().split(".")
    return labels[-2] if len(labels) >= 2 else labels[0]


def _nvd_score(metrics: dict):
    for key, version in (("cvssMetricV31", "3.1"), ("cvssMetricV40", "4.0"),
                         ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        entries = metrics.get(key) or []
        if not entries:
            continue
        metric = next((m for m in entries if m.get("type") == "Primary"), entries[0])
        data = metric.get("cvssData") or {}
        severity = data.get("baseSeverity") or metric.get("baseSeverity")
        return data.get("baseScore"), version, (severity or "").upper() or None
    return None, None, None


def parse_nvd(cve: dict, max_age_days: int) -> dict | None:
    published = cve.get("published")
    pub = parse_time(published)
    if pub and datetime.now(timezone.utc) - pub > timedelta(days=max_age_days):
        return None
    vendor = product = None
    for conf in cve.get("configurations") or []:
        for node in conf.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                parts = (match.get("criteria") or "").split(":")
                if match.get("vulnerable") and len(parts) > 4:
                    vendor, product = parts[3], parts[4]
                    break
            if vendor:
                break
        if vendor:
            break
    partial = {
        "id": cve["id"],
        "description": next((d["value"] for d in cve.get("descriptions") or [] if d.get("lang") == "en"), None),
        "published": published,
        "status": cve.get("vulnStatus"),
        "cwe": sorted({d["value"] for w in cve.get("weaknesses") or [] for d in w.get("description") or []
                       if str(d.get("value", "")).startswith("CWE-")}),
        "vendor": vendor,
        "product": product,
        "cna": _cna(cve.get("sourceIdentifier")),
        "refs": {"NVD": f"https://nvd.nist.gov/vuln/detail/{cve['id']}"},
    }
    score, version, severity = _nvd_score(cve.get("metrics") or {})
    if score is not None:
        partial.update(cvss=float(score), cvss_version=version, severity=severity, score_source="nvd")
    if cve.get("cisaExploitAdd"):
        partial["kev"] = {"date_added": cve["cisaExploitAdd"], "name": cve.get("cisaVulnerabilityName")}
    return partial


class NVDSource(Source):
    seed_on_first_run = False

    async def poll(self, seed: bool) -> int:
        app = self.app
        state = await app.store.source_get(self.id)
        now = datetime.now(timezone.utc).replace(microsecond=0)
        cursor = parse_time(state.get("cursor"))
        if cursor:
            start = cursor - timedelta(minutes=10)
        else:
            start = now - timedelta(hours=float(self.cfg.get("first_run_lookback_hours", 6)))
        start = max(start, now - timedelta(days=119))

        headers = dict(JSON_ACCEPT)
        if app.cfg["secrets"]["nvd_api_key"]:
            headers["apiKey"] = app.cfg["secrets"]["nvd_api_key"]
        max_age = int(app.cfg["filters"]["vulns"]["max_age_days"])
        fmt = "%Y-%m-%dT%H:%M:%S.000"

        index, count = 0, 0
        while True:
            params = {
                "lastModStartDate": start.strftime(fmt), "lastModEndDate": now.strftime(fmt),
                "resultsPerPage": "2000", "startIndex": str(index),
            }
            fetched = await app.http.get(NVD_URL, params=params, headers=headers, conditional=False)
            data = json.loads(fetched.body)
            batch = data.get("vulnerabilities") or []
            for item in batch:
                partial = parse_nvd(item.get("cve") or {}, max_age)
                if partial:
                    await app.vulns.ingest(partial, seed=seed)
                    count += 1
            index += len(batch)
            if not batch or index >= int(data.get("totalResults") or 0):
                break
        await app.store.source_update(self.id, cursor=now.isoformat())
        return count


class KEVSource(Source):
    async def fetch(self):
        urls = [self.cfg.get("url") or KEV_URL, *self.cfg.get("fallback_urls", [KEV_MIRROR])]
        error = None
        for url in urls:
            try:
                fetched = await self.app.http.get(url, conditional=True, headers=JSON_ACCEPT)
            except FetchError as exc:
                log.warning("KEV %s failed (%s), trying the next source", url, exc)
                error = exc
                continue
            return fetched
        raise error

    async def poll(self, seed: bool) -> int:
        app = self.app
        fetched = await self.fetch()
        if fetched is None:
            return 0
        data = json.loads(fetched.body)
        app.kb.update_kev(data.get("vulnerabilities") or [])
        count = 0
        for v in data.get("vulnerabilities") or []:
            cve = (v.get("cveID") or "").upper()
            if not cve:
                continue
            key = "kev:" + cve
            if await app.store.seen_any([key]):
                continue
            await app.vulns.ingest({
                "id": cve,
                "title": v.get("vulnerabilityName"),
                "vendor": v.get("vendorProject"),
                "product": v.get("product"),
                "description": v.get("shortDescription"),
                "kev": {
                    "date_added": v.get("dateAdded"), "due": v.get("dueDate"),
                    "ransomware": v.get("knownRansomwareCampaignUse"),
                    "name": v.get("vulnerabilityName"),
                },
                "refs": {"CISA KEV": f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={cve}"},
            }, seed=seed)
            await app.store.mark_seen([key], self.id)
            count += 1
        await app.http.commit(fetched)
        return count


def _ghsa_score(adv: dict):
    severities = adv.get("cvss_severities") or {}
    for key, version in (("cvss_v3", "3.1"), ("cvss_v4", "4.0")):
        score = (severities.get(key) or {}).get("score")
        if score:
            return float(score), version
    legacy = (adv.get("cvss") or {}).get("score")
    return (float(legacy), "3.x") if legacy else (None, None)


def _first_paragraph(markdown: str | None) -> str | None:
    if not markdown:
        return None
    for block in re.split(r"\n\s*\n", markdown):
        text = " ".join(line.strip() for line in block.splitlines() if not line.strip().startswith("#")).strip()
        if len(text) > 40:
            return text[:700]
    return markdown.strip()[:700] or None


class GHSASource(Source):
    async def poll(self, seed: bool) -> int:
        app = self.app
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if app.cfg["secrets"]["github_token"]:
            headers["Authorization"] = f"Bearer {app.cfg['secrets']['github_token']}"
        params = {"type": "reviewed", "sort": "published", "direction": "desc",
                  "per_page": str(self.cfg.get("per_page", 100))}
        fetched = await app.http.get(GHSA_URL, params=params, headers=headers, conditional=True)
        if fetched is None:
            return 0
        count = 0
        for adv in reversed(json.loads(fetched.body)):
            ghsa_id = adv.get("ghsa_id")
            if not ghsa_id or await app.store.seen_any(["ghsa:" + ghsa_id]):
                continue
            cve = adv.get("cve_id")
            severity = (adv.get("severity") or "").upper().replace("MODERATE", "MEDIUM")
            score, version = _ghsa_score(adv)
            packages = sorted({
                f"{v['package']['ecosystem']}:{v['package']['name']}"
                for v in adv.get("vulnerabilities") or [] if v.get("package")
            })
            partial = {
                "id": cve or ghsa_id,
                "aliases": [ghsa_id] + ([cve] if cve else []),
                "title": adv.get("summary"),
                "description": _first_paragraph(adv.get("description")),
                "published": adv.get("published_at"),
                "packages": packages,
                "cwe": [c["cwe_id"] for c in adv.get("cwes") or [] if c.get("cwe_id")],
                "refs": {"GitHub Advisory": adv.get("html_url")},
                "severity": severity if severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else None,
                "score_source": "ghsa",
            }
            if score:
                partial.update(cvss=score, cvss_version=version)
            await app.vulns.ingest(partial, seed=seed)
            await app.store.mark_seen(["ghsa:" + ghsa_id], self.id)
            count += 1
        await app.http.commit(fetched)
        return count


class EPSSSource(Source):
    seed_on_first_run = False

    async def poll(self, seed: bool) -> int:
        app = self.app
        since = time.time() - float(self.cfg.get("track_days", 14)) * 86400
        cves = sorted({primary_id(d) for _, d in await app.store.vulns_recent(since)})
        cves = [c for c in cves if c.startswith("CVE-")]
        count = 0
        for i in range(0, len(cves), 100):
            chunk = cves[i:i + 100]
            fetched = await app.http.get(EPSS_URL, params={"cve": ",".join(chunk), "limit": "100"},
                                         headers=JSON_ACCEPT, conditional=False)
            for row in json.loads(fetched.body).get("data") or []:
                await app.vulns.ingest({"id": row["cve"], "epss": float(row["epss"]),
                                        "epss_pct": float(row.get("percentile") or 0)}, seed=False)
                count += 1
        return count
