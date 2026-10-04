from __future__ import annotations

import json
import re
from datetime import date, datetime, time, timedelta
from zoneinfo import ZoneInfo

from bs4 import BeautifulSoup

UPDATES_URL = "https://api.msrc.microsoft.com/cvrf/v3.0/updates"
RELEASE_PAGES = (
    "https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information",
    "https://learn.microsoft.com/en-us/windows/release-health/release-information",
    "https://learn.microsoft.com/en-us/windows/release-health/windows-server-release-info",
)
DEFAULT_PRODUCTS = ["Windows 11", "Windows 10", "Windows Server 2019", "Windows Server 2022",
                    "Windows Server 2025"]
PACIFIC = ZoneInfo("America/Los_Angeles")
RELEASE_TIME = time(10, 0)
SEVERITY_RANK = {"Critical": 4, "Important": 3, "Moderate": 2, "Low": 1}
RELEASE_COLUMNS = {"Update type", "Availability date", "Build", "KB article"}
TSV_HEADER = ("CVE", "Title", "Component", "Severity", "Impact", "CVSS", "Exploited", "Publicly disclosed",
              "Affected products", "Fixed build")

_KB_RE = re.compile(r"\d{6,8}")
_ARCH_RE = re.compile(r"\s+for (32-bit|x64-based|ARM64-based) Systems$|\s+\(Server Core installation\)$",
                      re.IGNORECASE)
_CELL_RE = re.compile(r"[\t\r\n]+")
_SUPPORT_RE = re.compile(r"([A-Z][a-z]+ \d{1,2}, \d{4})\W+KB\s?(\d{6,8})(.*)", re.DOTALL)


def kb_url(kb: str) -> str:
    return f"https://support.microsoft.com/help/{kb}"


def cve_url(cve: str) -> str:
    return f"https://msrc.microsoft.com/update-guide/vulnerability/{cve}"


def doc_url(doc_id: str) -> str:
    return f"https://msrc.microsoft.com/update-guide/releaseNote/{doc_id}"


def tsv_name(kb: str) -> str:
    return f"KB{kb}-security-fixes.tsv"


def normalize_kb(value: str) -> str | None:
    match = _KB_RE.fullmatch(value.strip().upper().removeprefix("KB").strip())
    return match.group() if match else None


def short_build(build: str) -> str:
    return build.removeprefix("10.0.")


def version_label(product: str) -> str:
    return _ARCH_RE.sub("", product).replace(" version ", " Version ").strip()


def patch_tuesday(year: int, month: int) -> date:
    first = date(year, month, 1)
    return first + timedelta(days=(1 - first.weekday()) % 7 + 7)


def in_patch_window(now: datetime) -> bool:
    today = now.astimezone(PACIFIC).date()
    tuesday = patch_tuesday(today.year, today.month)
    return today in (tuesday, tuesday + timedelta(days=1))


def doc_month(doc_id: str) -> date | None:
    try:
        return datetime.strptime(doc_id, "%Y-%b").date()
    except ValueError:
        return None


def patch_time(doc_id: str) -> datetime | None:
    month = doc_month(doc_id)
    if month is None:
        return None
    return datetime.combine(patch_tuesday(month.year, month.month), RELEASE_TIME, tzinfo=PACIFIC)


def _threat_flags(vuln: dict) -> tuple[bool, bool]:
    for threat in vuln.get("Threats") or []:
        if threat.get("Type") != 1:
            continue
        pairs = dict(part.split(":", 1) for part in
                     ((threat.get("Description") or {}).get("Value") or "").split(";") if ":" in part)
        return (pairs.get("Exploited", "").strip().lower() == "yes",
                pairs.get("Publicly Disclosed", "").strip().lower() == "yes")
    return False, False


def _by_product(entries: list[dict], kind: int | None, field) -> dict[str, object]:
    out = {}
    for entry in entries or []:
        if kind is not None and entry.get("Type") != kind:
            continue
        value = field(entry)
        if value in (None, ""):
            continue
        for pid in entry.get("ProductID") or []:
            out.setdefault(pid, value)
    return out


def _pick(values: dict, pids: set[str], best):
    scoped = [values[p] for p in pids if p in values] or list(values.values())
    return best(scoped) if scoped else None


def finalize(entry: dict) -> dict:
    products = sorted({p for c in entry["cves"].values() for p in c["products"]})
    entry["products"] = products
    entry["versions"] = sorted({version_label(p) for p in products})
    entry["builds"] = sorted({b for c in entry["cves"].values() for b in c["builds"]})
    return entry


def parse_document(body: bytes, patterns: list[str]) -> dict:
    doc = json.loads(body)
    tracking = doc.get("DocumentTracking") or {}
    names = {p["ProductID"]: p["Value"] for p in (doc.get("ProductTree") or {}).get("FullProductName") or []}
    prefixes = tuple(p.lower() for p in patterns)
    scoped = {pid for pid, name in names.items() if name.lower().startswith(prefixes)}
    doc_id = ((tracking.get("Identification") or {}).get("ID") or {}).get("Value")

    kbs: dict[str, dict] = {}
    exploited, disclosed = [], []
    vulns = doc.get("Vulnerability") or []
    for vuln in vulns:
        cve = vuln.get("CVE")
        if not cve:
            continue
        title = (vuln.get("Title") or {}).get("Value") or ""
        is_exploited, is_disclosed = _threat_flags(vuln)
        if is_exploited:
            exploited.append({"cve": cve, "title": title})
        if is_disclosed:
            disclosed.append({"cve": cve, "title": title})

        fixes: dict[str, dict] = {}
        for rem in vuln.get("Remediations") or []:
            if rem.get("Type") != 2:
                continue
            kb = str((rem.get("Description") or {}).get("Value") or "").strip()
            pids = [p for p in rem.get("ProductID") or [] if p in scoped]
            if not _KB_RE.fullmatch(kb) or not pids:
                continue
            fix = fixes.setdefault(kb, {"pids": set(), "builds": set(), "subtype": None, "supersedes": set()})
            fix["pids"].update(pids)
            if rem.get("FixedBuild"):
                fix["builds"].add(rem["FixedBuild"])
            fix["subtype"] = fix["subtype"] or rem.get("SubType")
            fix["supersedes"].update(_KB_RE.findall(str(rem.get("Supercedence") or "")))
        if not fixes:
            continue

        component = next((n.get("Title") or n.get("Value") or "" for n in vuln.get("Notes") or []
                          if n.get("Type") == 7), "")
        threats = vuln.get("Threats") or []
        severities = _by_product(threats, 3, lambda t: (t.get("Description") or {}).get("Value"))
        impacts = _by_product(threats, 0, lambda t: (t.get("Description") or {}).get("Value"))
        scores = _by_product(vuln.get("CVSSScoreSets"), None, lambda s: s.get("BaseScore"))
        for kb, fix in fixes.items():
            entry = kbs.setdefault(kb, {"kb": kb, "subtype": None, "supersedes": [], "cves": {}})
            entry["subtype"] = entry["subtype"] or fix["subtype"]
            entry["supersedes"] = sorted(set(entry["supersedes"]) | fix["supersedes"])
            entry["cves"][cve] = {
                "doc": doc_id,
                "title": title,
                "component": component,
                "severity": _pick(severities, fix["pids"], lambda v: max(v, key=lambda s: SEVERITY_RANK.get(s, 0))),
                "impact": _pick(impacts, fix["pids"], lambda v: v[0]),
                "cvss": _pick(scores, fix["pids"], max),
                "exploited": is_exploited,
                "disclosed": is_disclosed,
                "products": sorted(names[p] for p in fix["pids"]),
                "builds": sorted(fix["builds"]),
            }

    revisions = tracking.get("RevisionHistory") or []
    return {
        "id": doc_id,
        "title": (doc.get("DocumentTitle") or {}).get("Value") or doc_id,
        "released": tracking.get("CurrentReleaseDate"),
        "revision": str(revisions[0].get("Number")) if revisions else None,
        "total": len(vulns),
        "exploited": exploited,
        "disclosed": disclosed,
        "kbs": {kb: finalize(entry) for kb, entry in kbs.items()},
    }


def kb_counts(d: dict) -> dict:
    cves = d["cves"].values()
    return {
        "cves": len(d["cves"]),
        "components": len({c["component"] for c in cves if c["component"]}),
        "critical": sum(1 for c in cves if c["severity"] == "Critical"),
        "exploited": sum(1 for c in cves if c["exploited"]),
        "disclosed": sum(1 for c in cves if c["disclosed"]),
    }


def _plural(count: int, noun: str = "CVE") -> str:
    return f"{count} {noun}{'' if count == 1 else 's'}"


def _named(cves: list[str], suffix: str) -> list[str]:
    parts = [f"{cve} {suffix}" for cve in cves[:3]]
    if len(cves) > 3:
        parts.append(f"{_plural(len(cves) - 3, 'more CVE')} {suffix}")
    return parts


def diff_kb(old: dict, new: dict) -> list[str]:
    before, after = old["cves"], new["cves"]
    added = sorted(set(after) - set(before))
    removed = sorted(set(before) - set(after))
    common = sorted(set(before) & set(after))
    parts = []
    if added:
        parts.append(f"{_plural(len(added))} added")
    if removed:
        parts.append(f"{_plural(len(removed))} removed")
    parts += _named([c for c in sorted(after) if after[c]["exploited"] and not (before.get(c) or {}).get("exploited")],
                    "now marked exploited")
    parts += _named([c for c in sorted(after) if after[c]["disclosed"] and not (before.get(c) or {}).get("disclosed")],
                    "now publicly disclosed")
    severity = [c for c in common if before[c]["severity"] != after[c]["severity"]]
    if severity:
        parts.append(f"severity changed for {_plural(len(severity))}")
    scores = [c for c in common if before[c]["cvss"] != after[c]["cvss"]]
    if scores:
        parts.append(f"CVSS changed for {_plural(len(scores))}")
    if old.get("builds") != new.get("builds") and new.get("builds"):
        parts.append("fixed build now " + ", ".join(short_build(b) for b in new["builds"]))
    return parts


def revision_line(kb: str, parts: list[str], jump_url: str | None) -> str:
    line = f"KB{kb} revised: {', '.join(parts)}"
    return f"{line} · [original card]({jump_url})" if jump_url else line


def _cell(value) -> str:
    return _CELL_RE.sub(" ", "" if value is None else str(value)).strip()


def kb_tsv(d: dict) -> bytes:
    def order(item):
        cve, c = item
        return (not c["exploited"], not c["disclosed"], -SEVERITY_RANK.get(c["severity"], 0),
                -(c["cvss"] or 0), cve)

    lines = ["\t".join(TSV_HEADER)]
    for cve, c in sorted(d["cves"].items(), key=order):
        lines.append("\t".join(_cell(v) for v in (
            cve, c["title"], c["component"], c["severity"], c["impact"], c["cvss"],
            "Yes" if c["exploited"] else "No", "Yes" if c["disclosed"] else "No",
            "; ".join(c["products"]), "; ".join(c["builds"]))))
    return ("\n".join(lines) + "\n").encode("utf-8")


def parse_release_tables(html: bytes | str) -> list[tuple[str, str, str, str]]:
    rows = []
    for table in BeautifulSoup(html, "html.parser").find_all("table"):
        trs = table.find_all("tr")
        if not trs:
            continue
        head = [c.get_text(" ", strip=True) for c in trs[0].find_all(["th", "td"])]
        if "Month" in head or not RELEASE_COLUMNS <= set(head):
            continue
        col = {name: i for i, name in enumerate(head)}
        for tr in trs[1:]:
            cells = [c.get_text(" ", strip=True) for c in tr.find_all("td")]
            if len(cells) != len(head):
                continue
            kb = _KB_RE.search(cells[col["KB article"]])
            kind = cells[col["Update type"]].split()
            if kb and cells[col["Build"]]:
                rows.append((kb.group(), cells[col["Build"]], cells[col["Availability date"]],
                             kind[-1].upper() if kind else ""))
    return rows


def parse_support_title(html: bytes | str, kb: str) -> tuple[str, str | None] | None:
    heading = BeautifulSoup(html, "html.parser").find("h1")
    match = _SUPPORT_RE.search(heading.get_text(" ", strip=True)) if heading else None
    if not match or match.group(2) != kb:
        return None
    try:
        released = datetime.strptime(match.group(1), "%B %d, %Y").date()
    except ValueError:
        return None
    tail = match.group(3).lower()
    if "out-of-band" in tail:
        kind = "OOB"
    elif "preview" in tail:
        kind = "D"
    elif released == patch_tuesday(released.year, released.month):
        kind = "B"
    else:
        kind = None
    return released.isoformat(), kind


def release_label(kind: str | None, subtype: str | None) -> str:
    if "servicing stack" in (subtype or "").lower():
        return "Servicing stack update"
    if kind == "B":
        return "Security update (Patch Tuesday)"
    if kind in ("C", "D"):
        return "Optional preview"
    if kind == "OOB":
        return "Out-of-band"
    return (subtype or "Security update").capitalize()
