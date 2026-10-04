from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from . import incidents
from .http import FetchError
from .kb import KEV_URLS
from .sources.sec_incidents import fetch_text, record_filing, sec_headers
from .util import parse_claim, parse_time

log = logging.getLogger(__name__)

HISTORY_START = "2023-12-18"
EARNINGS_YEARS = 3
DONE_KEY = "backfill.events"


async def from_local_tables(app) -> dict[str, int]:
    store, ev, companies = app.store, app.events, app.companies
    counts: dict[str, int] = {}

    def bump(kind: str, created: bool) -> None:
        if created:
            counts[kind] = counts.get(kind, 0) + 1

    rows = await store._all("SELECT id, ts, data FROM fin_items ORDER BY id")
    for row in rows:
        d = json.loads(row["data"])
        when = parse_time(d.get("published")) or datetime.fromtimestamp(row["ts"], timezone.utc)
        if d.get("event") == "mna":
            for ticker in d.get("tickers") or []:
                _, created = await ev.record("mna.announce", ticker=ticker, occurred_at=when, dedup=f"fin:{row['id']}",
                                             refs={"url": d["url"]}, payload={"title": d["title"], "role": "unknown"})
                bump("mna.announce", created)
        if d.get("event") == "earnings" and d.get("kind") == "filing" and "8-K" in d.get("title", ""):
            for ticker in d.get("tickers") or []:
                acc = d["url"].rstrip("/").split("/")[-1].replace("-index.htm", "")
                _, created = await ev.record("earnings.report", ticker=ticker, occurred_at=when, dedup=acc,
                                             refs={"filing": d["url"], "accession": acc}, payload={"title": d["title"]})
                bump("earnings.report", created)

    for row in await store._all("SELECT vid, data, first_seen, updated FROM vulns ORDER BY vid"):
        await vuln_events(app, json.loads(row["data"]), backfill_time=row["updated"], counts=counts)

    for row in await store._all("SELECT id, ts, data, channel_id, message_id FROM stories ORDER BY id"):
        d = json.loads(row["data"])
        post = [row["channel_id"], row["message_id"]] if row["message_id"] else None
        claim = d.get("claim") or parse_claim(d["title"])
        when = d.get("published") or datetime.fromtimestamp(row["ts"], timezone.utc).isoformat()
        if claim:
            company = companies.resolve(claim["victim"])
            if company:
                _, created = await ev.record(
                    "ransomware.claim.public", ticker=company.ticker, cik=company.cik, company=company.name,
                    occurred_at=when, dedup=f"story:{row['id']}", confidence=company.confidence,
                    refs={"story": row["id"], "url": d["url"], **({"post": post} if post else {})},
                    payload={"group": claim["group"], "victim": claim["victim"], "match": company.method})
                bump("ransomware.claim.public", created)
        elif d.get("also"):
            _, labels = app.intel.analyze(d["title"], d.get("summary") or "", source=d["source"])
            if "breach" in labels:
                for company in companies.find_in_text(d["title"]):
                    _, created = await ev.record(
                        "breach.news.public", ticker=company.ticker, cik=company.cik, company=company.name,
                        occurred_at=when, dedup=f"story:{row['id']}", confidence=company.confidence,
                        refs={"story": row["id"], "url": d["url"], **({"post": post} if post else {})},
                        payload={"title": d["title"], "outlets": 1 + len(d["also"]), "match": company.method})
                    bump("breach.news.public", created)
    return counts


async def vuln_events(app, d: dict, *, backfill_time: int | None = None, counts: dict | None = None) -> None:
    ticker = app.companies.exposure_ticker(d.get("vendor"))
    kev = d.get("kev") or {}
    if not ticker and kev.get("vendor"):
        ticker = app.companies.exposure_ticker(kev["vendor"])
    if not ticker:
        return
    vid = d["id"]
    if kev:
        when = datetime.fromtimestamp(kev["seen"], timezone.utc) if kev.get("seen") else kev.get("date_added")
        if when:
            _, created = await app.events.record(
                "kev.vendor", ticker=ticker, occurred_at=when, dedup=vid, date_only=not kev.get("seen"),
                refs={"cve": vid}, payload={"vendor": d.get("vendor"), "product": d.get("product"),
                                            "name": kev.get("name")})
            if counts is not None and created:
                counts["kev.vendor"] = counts.get("kev.vendor", 0) + 1
    critical = bool(kev) or (d.get("cvss") or 0) >= 9
    if critical and len(d.get("news") or []) >= 2:
        when = datetime.fromtimestamp(backfill_time, timezone.utc) if backfill_time else datetime.now(timezone.utc)
        _, created = await app.events.record(
            "vuln.vendor_critical", ticker=ticker, occurred_at=when, dedup=vid, refs={"cve": vid},
            payload={"cvss": d.get("cvss"), "kev": bool(kev), "outlets": len(d.get("news") or [])})
        if counts is not None and created:
            counts["vuln.vendor_critical"] = counts.get("vuln.vendor_critical", 0) + 1


async def _acceptance_times(app, cik: int) -> dict[str, str]:
    try:
        fetched = await app.http.get(incidents.SUBMISSIONS_URL.format(cik=cik),
                                     headers=sec_headers(app, "application/json"), conditional=False)
    except FetchError as exc:
        log.info("submissions for CIK %s unavailable: %s", cik, exc)
        return {}
    recent = json.loads(fetched.body).get("filings", {}).get("recent", {})
    return dict(zip(recent.get("accessionNumber", []), recent.get("acceptanceDateTime", [])))


async def _efts(app, query: str, items: str) -> list[dict]:
    today = datetime.now(timezone.utc).date().isoformat()
    hits, offset = [], 0
    while True:
        params = {"q": query, "items": items, "forms": "8-K", "dateRange": "custom", "startdt": HISTORY_START,
                  "enddt": today, "from": str(offset)}
        fetched = await app.http.get(incidents.EFTS_URL, params=params, headers=sec_headers(app, "application/json"),
                                     conditional=False)
        data = json.loads(fetched.body)["hits"]
        batch = data["hits"]
        hits += batch
        if not batch or len(hits) >= data["total"]["value"]:
            return hits
        offset += len(batch)


async def filings_history(app, query: str, items: str, limit: int | None = None) -> dict[str, int]:
    hits = await _efts(app, query, items)
    if limit:
        hits = hits[:limit]
    times: dict[int, dict[str, str]] = {}
    counts: dict[str, int] = {}
    for hit in sorted(hits, key=lambda h: h["_source"]["file_date"]):
        src = hit["_source"]
        accession, _, filename = hit["_id"].partition(":")
        cik = int(src["ciks"][0])
        if cik not in times:
            times[cik] = await _acceptance_times(app, cik)
        accepted, date_only = times[cik].get(accession), False
        if not accepted:
            accepted, date_only = src["file_date"], True
        doc_url = f"https://www.sec.gov/Archives/edgar/data/{cik}/{accession.replace('-', '')}/{filename}"
        try:
            text = await fetch_text(app, doc_url)
        except FetchError as exc:
            log.info("backfill: %s unavailable: %s", doc_url, exc)
            continue
        name = (src.get("display_names") or [""])[0].split("  (")[0]
        event_id, created = await record_filing(
            app, form=src["form"], cik=cik, company=name, accession=accession, items=src.get("items") or [],
            accepted=accepted, doc_url=doc_url, text=text,
            index_url=f"https://www.sec.gov/Archives/edgar/data/{cik}/{accession.replace('-', '')}/{accession}-index.htm",
            date_only=date_only)
        if created:
            ev = await app.store.event_get(event_id)
            counts[ev["type"]] = counts.get(ev["type"], 0) + 1
    return counts


async def kev_history(app) -> dict[str, int]:
    data, error = None, None
    for url in KEV_URLS:
        try:
            fetched = await app.http.get(url, headers={"Accept": "application/json"}, conditional=False)
            data = json.loads(fetched.body)
            break
        except FetchError as exc:
            error = exc
    if data is None:
        raise error
    counts = {}
    for v in data.get("vulnerabilities") or []:
        ticker = app.companies.exposure_ticker(v.get("vendorProject"))
        if not ticker or not v.get("dateAdded"):
            continue
        _, created = await app.events.record(
            "kev.vendor", ticker=ticker, occurred_at=v["dateAdded"], dedup=v["cveID"].upper(), date_only=True,
            refs={"cve": v["cveID"].upper()}, payload={"vendor": v.get("vendorProject"), "product": v.get("product"),
                                                       "name": v.get("vulnerabilityName")})
        if created:
            counts["kev.vendor"] = counts.get("kev.vendor", 0) + 1
    return counts


async def earnings_history(app) -> dict[str, int]:
    counts = {}
    cutoff = datetime.now(timezone.utc).replace(year=datetime.now(timezone.utc).year - EARNINGS_YEARS)
    for ticker, info in app.finance.watch.companies.items():
        if not info.get("cik"):
            continue
        cik = int(info["cik"])
        try:
            fetched = await app.http.get(incidents.SUBMISSIONS_URL.format(cik=cik),
                                         headers=sec_headers(app, "application/json"), conditional=False)
        except FetchError as exc:
            log.info("earnings backfill for %s failed: %s", ticker, exc)
            continue
        recent = json.loads(fetched.body).get("filings", {}).get("recent", {})
        for acc, form, items, accepted in zip(recent.get("accessionNumber", []), recent.get("form", []),
                                              recent.get("items", []), recent.get("acceptanceDateTime", [])):
            when = parse_time(accepted)
            if form != "8-K" or "2.02" not in (items or "").split(",") or not when or when < cutoff:
                continue
            _, created = await app.events.record(
                "earnings.report", ticker=ticker, cik=cik, company=info.get("name"), occurred_at=when, dedup=acc,
                refs={"accession": acc, "filing": f"https://www.sec.gov/Archives/edgar/data/{cik}/"
                                                  f"{acc.replace('-', '')}/{acc}-index.htm"},
                payload={"items": items})
            if created:
                counts["earnings.report"] = counts.get("earnings.report", 0) + 1
    return counts


async def run(app, *, steps: tuple[str, ...] = ("1.05", "8.01", "kev", "earnings")) -> dict[str, dict[str, int]]:
    out = {}
    jobs = {"1.05": lambda: filings_history(app, "", "1.05"),
            "8.01": lambda: filings_history(app, '"cybersecurity incident"', "8.01"),
            "kev": lambda: kev_history(app), "earnings": lambda: earnings_history(app)}
    for step in steps:
        key = f"{DONE_KEY}.{step}"
        if await app.store.setting_get(key):
            out[step] = {"skipped": 1}
            continue
        try:
            out[step] = await jobs[step]()
        except Exception as exc:
            log.warning("event backfill step %s failed: %s", step, exc)
            out[step] = {"failed": 1}
            continue
        await app.store.setting_set(key, str(int(datetime.now(timezone.utc).timestamp())))
    return out
