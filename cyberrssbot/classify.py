from __future__ import annotations

import re

from .extract import Extraction, extract

LABELS = ("exploited", "vulnerability", "ransomware", "breach", "apt", "malware", "supply-chain", "policy-law",
          "law-enforcement", "finance")
DEFAULT_WEIGHTS = {
    "base": 1.0, "outlet": 1.0, "outlet_cap": 5, "kev": 5.0, "cvss": 3.0, "watchlist": 1.5, "named": 1.5,
    "figures": 1.0, "primary": 2.0, "half_life_hours": 24.0,
}

_KEYWORDS = {
    "exploited": re.compile(r"\bactively exploited\b|\bexploited in the wild\b|\bin-the-wild\b|\bzero-days?\b|"
                            r"\b0-days?\b|\bunder active (?:attack|exploitation)\b|\bmass exploitation\b|"
                            r"\bknown exploited\b", re.IGNORECASE),
    "vulnerability": re.compile(r"\bvulnerabilit(?:y|ies)\b|\bzero-days?\b|\b0-days?\b|\bflaws?\b|\bsecurity bugs?\b|\bRCE\b|"
                                r"\bremote code execution\b|\bprivilege escalation\b|\bauth(?:entication)? bypass\b|"
                                r"\bPatch Tuesday\b|\bsecurity (?:update|patch|advisory)\b|\bSQL injection\b|"
                                r"\bproof-of-concept\b|\bPoC exploit\b", re.IGNORECASE),
    "ransomware": re.compile(r"\bransomware\b|\bextortion\b|\bleak site\b|\bdouble[- ]extortion\b|\bransom\b",
                             re.IGNORECASE),
    "breach": re.compile(r"\bdata breach\b|\bbreach(?:ed|es)?\b|\bdata (?:leak|theft)\b|\bleaked\b|"
                         r"\bstolen data\b|\bexposed (?:data|records|database)\b|\bcyber ?attack\b|\bhacked\b",
                         re.IGNORECASE),
    "apt": re.compile(r"\bAPT\d*\b|\bstate-sponsored\b|\bstate-backed\b|\bnation-state\b|\bespionage\b|"
                      r"\bthreat actors?\b|\bhacking group\b|\bstate hackers\b", re.IGNORECASE),
    "malware": re.compile(r"\bmalware\b|\btrojan\b|\bbackdoors?\b|\b(?:info)?stealers?\b|\bbotnets?\b|"
                          r"\bloaders?\b|\bwipers?\b|\bspyware\b|\bRAT\b|\brootkits?\b|\bworm\b|\bcryptominers?\b|"
                          r"\bkeyloggers?\b", re.IGNORECASE),
    "supply-chain": re.compile(r"\bsupply[- ]chain\b|\bnpm\b|\bPyPI\b|\bRubyGems\b|\bNuGet\b|\bcrates\.io\b|"
                               r"\bMaven\b|\bGo modules?\b|\bmalicious packages?\b|\btyposquat\w*\b|"
                               r"\bdependency confusion\b|\bVS ?Code extensions?\b|\bGitHub Actions?\b|"
                               r"\bDocker Hub\b|\bGHSA-[\w-]+\b", re.IGNORECASE),
    "policy-law": re.compile(r"\bregulat(?:or|ors|ion|ions|ory)\b|\blegislation\b|\blawmakers?\b|\bdirective\b|"
                             r"\bprivacy law\b|\bdata protection (?:law|authority|rules)\b|"
                             r"\bexecutive order\b|\bsanction(?:s|ed)\b|\bclass action\b|\blawsuit\b",
                             re.IGNORECASE),
    "law-enforcement": re.compile(r"\bEuropol\b|\bInterpol\b|\bJustice Department\b|\bDOJ\b|"
                                  r"\bNational Crime Agency\b|\bpolice\b|\blaw enforcement\b|\btakedown\b|"
                                  r"\bseiz(?:ed|es|ure)\b|\bextradit\w+\b|\bsentenced\b|\bpleads? guilty\b|"
                                  r"\bprosecutors?\b|\bdismantl\w+\b", re.IGNORECASE),
    "finance": re.compile(r"\bacquir(?:es|ed|ing)\b|\bacquisition\b|\bfunding round\b|\bSeries [A-F]\b|\bIPO\b|"
                          r"\bearnings\b|\bquarterly results\b|\bto buy\b|\bmerger\b|\bvaluation\b",
                          re.IGNORECASE),
}
_VULN_CONTEXT = re.compile(r"\bvulnerabilit|\bflaw|\bbug\b|\bzero-day|\bCVE-", re.IGNORECASE)


def classify(text: str, ex: Extraction, *, kind: str = "story", vuln: dict | None = None,
             extra: tuple[str, ...] = ()) -> list[str]:
    labels = set(extra)
    if kind == "vuln":
        vuln = vuln or {}
        labels.add("vulnerability")
        if vuln.get("kev"):
            labels.add("exploited")
        if vuln.get("packages") or any(a.startswith("GHSA-") for a in [vuln.get("id", ""), *vuln.get("aliases", [])]):
            labels.add("supply-chain")
        return [label for label in LABELS if label in labels]
    if kind == "finance":
        labels.add("finance")
    hit = {label for label, rx in _KEYWORDS.items() if rx.search(text)}

    if ex.cves or "vulnerability" in hit or (
            "patched" in ex.actions and (ex.entities["vendor"] or ex.entities["product"])):
        labels.add("vulnerability")
    if "exploited" in hit or ("exploited" in ex.actions and (ex.cves or _VULN_CONTEXT.search(text))):
        labels.add("exploited")
    if ex.ransomware or "ransomware" in hit:
        labels.add("ransomware")
    if "breach" in hit or "breached" in ex.actions:
        labels.add("breach")
    if "apt" in hit or (ex.entities["actor"] and "ransomware" not in labels):
        labels.add("apt")
    if ex.entities["malware"] or "malware" in hit:
        labels.add("malware")
    if "supply-chain" in hit:
        labels.add("supply-chain")
    if ex.entities["regulator"] or "policy-law" in hit or "fined" in ex.actions:
        labels.add("policy-law")
    if "law-enforcement" in hit or {"arrested", "indicted"} & set(ex.actions):
        labels.add("law-enforcement")
    if "finance" in hit or "acquired" in ex.actions:
        labels.add("finance")
    return [label for label in LABELS if label in labels]


def score(ex: Extraction, *, weights: dict, outlets: int = 0, kev: bool = False, cvss: float | None = None,
          watched: bool = False, primary: bool = False, age_hours: float = 0.0) -> float:
    w = {**DEFAULT_WEIGHTS, **(weights or {})}
    total = float(w["base"])
    total += w["outlet"] * min(outlets, int(w["outlet_cap"]))
    if kev:
        total += w["kev"]
    if cvss is not None:
        total += w["cvss"] * max(0.0, min(float(cvss), 10.0)) / 10.0
    if watched:
        total += w["watchlist"]
    if ex.named():
        total += w["named"]
    if ex.money or ex.counts:
        total += w["figures"]
    if primary:
        total += w["primary"]
    half_life = float(w["half_life_hours"])
    if half_life > 0:
        total *= 0.5 ** (max(age_hours, 0.0) / half_life)
    return round(total, 3)


class Intel:
    def __init__(self, cfg: dict, kb, watch_re=None):
        self.kb = kb
        self.watch_re = watch_re
        self.weights = {**DEFAULT_WEIGHTS, **((cfg.get("digest") or {}).get("weights") or {})}
        self.routes = [(channel, frozenset(rule.get("labels") or []))
                       for channel, rule in (cfg.get("routing") or {}).items()
                       if isinstance(rule, dict) and rule.get("enabled", True) and rule.get("labels")]
        sources = cfg.get("sources") or []
        self.primary = {(s.get("name") or s["id"]) for s in sources if s.get("primary")}
        self.source_labels = {(s.get("name") or s["id"]): tuple(l for l in s.get("labels") or [] if l in LABELS)
                              for s in sources if s.get("labels")}
        self.no_quote = {(s.get("name") or s["id"]) for s in sources if s.get("quote") is False}
        self.outlets = sorted({(s.get("name") or s["id"]) for s in sources}, key=lambda n: (-len(n), n))

    def watched(self, text: str) -> bool:
        return bool(self.watch_re and self.watch_re.search(text.lower().replace("_", " ")))

    def analyze(self, title: str, summary: str = "", *, kind: str = "story", vuln: dict | None = None,
                source: str | None = None) -> tuple[Extraction, list[str]]:
        text = f"{title}. {summary}" if summary else title
        ex = extract(text, self.kb)
        return ex, classify(text, ex, kind=kind, vuln=vuln, extra=self.source_labels.get(source, ()))

    def route(self, labels: list[str], default: str, usable=None) -> str:
        for channel, wanted in self.routes:
            if wanted & set(labels) and (usable is None or usable(channel)):
                return channel
        return default
