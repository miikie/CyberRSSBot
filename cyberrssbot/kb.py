from __future__ import annotations

import asyncio
import csv
import io
import json
import logging
import os
import re
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .http import FetchError

ATTACK_URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
              "enterprise-attack/enterprise-attack.json")
MISP_ACTORS_URL = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json"
CWE_URL = "https://cwe.mitre.org/data/csv/1000.csv.zip"
KEV_URLS = ("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json")
ATTACK_TIMEOUT = 300
TYPE_ORDER = ("actor", "malware", "vendor", "product", "regulator", "country")
ATTACK_TYPES = {"intrusion-set": ("actor", "group"), "malware": ("malware", "malware"), "tool": ("malware", "tool")}
PRODUCT_STOP = {"multiple products", "multiple devices", "multiple", "n/a", "unknown"}
CUE_WINDOW = 4
THREAT_CUES = frozenset("""
    ransomware gang group groups malware trojan backdoor stealer infostealer botnet loader rat apt actor actors
    hackers hacker operators operator affiliate affiliates wiper spyware implant worm c2 campaign crew espionage
    tool utility beacon variant family banking dropper rootkit miner cryptominer extortion locker encryptor
    threat cybercrime cybercriminals attackers intrusion
""".split())
VENDOR_CUES = frozenset("""
    patches patched patch fixes fixed fix warns warned releases released says said confirms confirmed discloses
    disclosed issues issued addresses addressed urges rolls ships pushes vulnerability vulnerabilities flaw flaws
    bug bugs zero-day update updates advisory exploit exploited security cve
""".split())

TOKEN_RE = re.compile(r"[^\W_]+(?:[-.&+][^\W_]+)*")
_BOUNDARY_RE = re.compile(r"[.!?:;|\n]")
_SLUG_RE = re.compile(r"[^a-z0-9]+")
_CWE_SHORT_RE = re.compile(r"\('([^']+)'\)\s*$")
_PAREN_RE = re.compile(r"\([^)]*\)")
_PRODUCT_SPLIT_RE = re.compile(r",\s*(?:and\s+)?|\s+and\s+|\s+&\s+")

log = logging.getLogger(__name__)


@dataclass
class Entity:
    id: str
    type: str
    name: str
    kind: str
    source: str
    aliases: list[str] = field(default_factory=list)
    meta: dict = field(default_factory=dict)

    def names(self) -> list[str]:
        return [self.name, *[a for a in self.aliases if a != self.name]]


@dataclass(frozen=True)
class Alias:
    entity: Entity
    tokens: tuple[str, ...]
    rule: str


@dataclass(frozen=True)
class Match:
    start: int
    end: int
    text: str
    entity: Entity


def tokenize(text: str) -> list[str]:
    return TOKEN_RE.findall(text)


def slug(value: str) -> str:
    return _SLUG_RE.sub("-", value.lower()).strip("-")


def alias_rule(tokens: tuple[str, ...], common: frozenset[str]) -> str | None:
    if len(tokens) != 1:
        return "plain"
    token = tokens[0]
    if len(token) > 3 and token.lower() not in common:
        return "plain"
    if any(c.isdigit() for c in token) or sum(c.isupper() for c in token) >= 2:
        return "acronym"
    if token.islower():
        return None
    return "word"


def iter_stix_objects(text: str):
    decoder = json.JSONDecoder()
    pos = text.index("[", text.index('"objects"')) + 1
    end = len(text)
    while pos < end:
        while pos < end and text[pos] in " \t\r\n,":
            pos += 1
        if pos >= end or text[pos] == "]":
            return
        obj, pos = decoder.raw_decode(text, pos)
        yield obj


def parse_attack(body: bytes) -> dict:
    entities, version = [], None
    for obj in iter_stix_objects(body.decode("utf-8")):
        kind = obj.get("type")
        if kind == "x-mitre-collection":
            version = obj.get("x_mitre_version")
        if kind not in ATTACK_TYPES or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        ext = next((r for r in obj.get("external_references") or [] if r.get("source_name") == "mitre-attack"), {})
        etype, ekind = ATTACK_TYPES[kind]
        aliases = [a for a in (obj.get("aliases") or obj.get("x_mitre_aliases") or []) if a != obj["name"]]
        entities.append({"id": ext.get("external_id") or obj["id"], "type": etype, "kind": ekind,
                         "name": obj["name"], "aliases": sorted(set(aliases)), "url": ext.get("url")})
    entities.sort(key=lambda e: (e["type"], e["id"]))
    return {"version": version, "entities": entities}


def parse_misp_actors(body: bytes) -> dict:
    data = json.loads(body)
    entities = []
    for value in data.get("values") or []:
        name = (value.get("value") or "").strip()
        if not name:
            continue
        synonyms = [s.strip() for s in (value.get("meta") or {}).get("synonyms") or [] if isinstance(s, str)]
        entities.append({"id": "misp:" + (value.get("uuid") or slug(name)), "type": "actor", "kind": "group",
                         "name": name, "aliases": sorted({s for s in synonyms if s and s != name})})
    entities.sort(key=lambda e: e["id"])
    return {"version": str(data.get("version") or ""), "entities": entities}


def parse_cwe(body: bytes) -> dict:
    archive = zipfile.ZipFile(io.BytesIO(body))
    member = next(n for n in archive.namelist() if n.lower().endswith(".csv"))
    rows = csv.DictReader(io.StringIO(archive.read(member).decode("utf-8-sig")))
    entities = []
    for row in rows:
        number, name = (row.get("CWE-ID") or "").strip(), (row.get("Name") or "").strip()
        if number.isdigit() and name:
            short = _CWE_SHORT_RE.search(name)
            entities.append({"id": f"CWE-{number}", "name": short.group(1) if short else name, "full_name": name})
    entities.sort(key=lambda e: int(e["id"][4:]))
    return {"version": None, "entities": entities}


def parse_kev(vulnerabilities: list[dict]) -> dict:
    vendors: dict[str, set[str]] = {}
    for vuln in vulnerabilities or []:
        vendor = (vuln.get("vendorProject") or "").strip()
        product = (vuln.get("product") or "").strip()
        if not vendor or vendor.lower() in PRODUCT_STOP:
            continue
        products = vendors.setdefault(vendor, set())
        for part in _PRODUCT_SPLIT_RE.split(_PAREN_RE.sub(" ", product)):
            part = " ".join(part.split())
            if part.lower().startswith(vendor.lower() + " "):
                part = part[len(vendor) + 1:]
            if len(part) >= 3 and part.lower() not in PRODUCT_STOP and part.lower() != vendor.lower() \
                    and "multiple" not in part.lower():
                products.add(part)
    return {"vendors": [{"name": v, "products": sorted(p)} for v, p in sorted(vendors.items())]}


class KnowledgeBase:
    def __init__(self, cfg: dict, vendors: list[str] | None = None):
        self.cfg = cfg
        self.extra_vendors = sorted(set(vendors or []))
        self.cache_dir = Path(cfg.get("cache_dir") or "kb_cache")
        extras = Path(cfg.get("extras_dir") or "kb")
        if not extras.is_dir() and not extras.is_absolute():
            extras = Path(__file__).resolve().parent.parent / extras
        self.extras_dir = extras
        self.refresh_seconds = float(cfg.get("refresh_days", 7)) * 86400
        self.entities: list[Entity] = []
        self.index: dict[tuple[str, ...], list[Alias]] = {}
        self.max_tokens = 1
        self.common: frozenset[str] = frozenset()
        self.vendor_tokens: frozenset[str] = frozenset()
        self.cwe: dict[str, str] = {}
        self.status: dict[str, str] = {}

    def _cache(self, name: str) -> Path:
        return self.cache_dir / f"{name}.json"

    def _read_cache(self, name: str) -> dict | None:
        try:
            return json.loads(self._cache(name).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    def _write_cache(self, name: str, payload: dict) -> None:
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        tmp = self._cache(name).with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=1, sort_keys=True), encoding="utf-8")
        os.replace(tmp, self._cache(name))

    def _extras(self, name: str) -> list[dict]:
        path = self.extras_dir / f"{name}.yaml"
        if not path.is_file():
            return []
        rows = yaml.safe_load(path.read_text(encoding="utf-8")) or []
        return [r if isinstance(r, dict) else {"name": str(r)} for r in rows]

    def load(self) -> None:
        words = self.extras_dir / "common_words.txt"
        self.common = frozenset(w.strip().lower() for w in words.read_text(encoding="utf-8").split()) \
            if words.is_file() else frozenset()

        self.cwe = {e["id"]: e["name"] for e in (self._read_cache("cwe") or {"entities": []})["entities"]}

        entities: list[Entity] = []
        actors: dict[str, Entity] = {}

        def add_actor(raw: dict, source: str, kind: str | None = None) -> None:
            names = [raw["name"], *(raw.get("aliases") or [])]
            known = next((actors[n.lower()] for n in names if n.lower() in actors), None)
            if known is None:
                known = Entity(id=raw.get("id") or f"{source}:{slug(raw['name'])}", type="actor", name=raw["name"],
                               kind=kind or raw.get("kind") or "group", source=source,
                               meta={k: raw[k] for k in ("url", "origin") if raw.get(k)})
                entities.append(known)
            elif kind == "ransomware":
                known.kind = "ransomware"
            for name in names:
                actors.setdefault(name.lower(), known)
                if name != known.name and name not in known.aliases:
                    known.aliases.append(name)

        attack = self._read_cache("attack") or {"entities": []}
        for raw in attack["entities"]:
            if raw["type"] == "actor":
                add_actor(raw, "attack")
        if self.cfg.get("use_misp", True):
            for raw in (self._read_cache("misp_actors") or {"entities": []})["entities"]:
                add_actor(raw, "misp")
        for raw in self._extras("actors"):
            add_actor(raw, "manual")
        for raw in self._extras("ransomware"):
            add_actor(raw, "manual", "ransomware")

        for raw in attack["entities"]:
            if raw["type"] == "malware":
                entities.append(Entity(id=raw["id"], type="malware", name=raw["name"], kind=raw["kind"],
                                       source="attack", aliases=list(raw.get("aliases") or []),
                                       meta={"url": raw["url"]} if raw.get("url") else {}))
        for raw in self._extras("malware"):
            entities.append(Entity(id=f"manual:{slug(raw['name'])}", type="malware", name=raw["name"],
                                   kind=raw.get("kind") or "malware", source="manual",
                                   aliases=list(raw.get("aliases") or [])))

        for raw in (self._read_cache("kev") or {"vendors": []})["vendors"]:
            entities.append(Entity(id=f"vendor:{slug(raw['name'])}", type="vendor", name=raw["name"], kind="vendor",
                                   source="kev"))
            for product in raw.get("products") or []:
                entities.append(Entity(id=f"product:{slug(raw['name'])}:{slug(product)}", type="product",
                                       name=product, kind="product", source="kev", meta={"vendor": raw["name"]}))
        known_vendors = {e.name.lower() for e in entities if e.type == "vendor"}
        for name in self.extra_vendors:
            if name.lower() not in known_vendors:
                entities.append(Entity(id=f"vendor:{slug(name)}", type="vendor", name=name, kind="vendor",
                                       source="watchlist"))
        for raw in self._extras("regulators"):
            entities.append(Entity(id=f"regulator:{slug(raw['name'])}", type="regulator", name=raw["name"],
                                   kind=raw.get("kind") or "regulator", source="manual",
                                   aliases=list(raw.get("aliases") or []),
                                   meta={k: raw[k] for k in ("jurisdiction", "full_name") if raw.get(k)}))
        for raw in self._extras("countries"):
            entities.append(Entity(id=f"country:{slug(raw['name'])}", type="country", name=raw["name"],
                                   kind="country", source="manual", aliases=list(raw.get("aliases") or [])))

        index: dict[tuple[str, ...], list[Alias]] = {}
        for entity in entities:
            entity.aliases.sort(key=str.lower)
            seen = set()
            for name in entity.names():
                tokens = tuple(tokenize(name))
                if not tokens or tokens in seen or not name.isascii():
                    continue
                seen.add(tokens)
                rule = alias_rule(tokens, self.common)
                if rule == "plain" and entity.type == "product" and len(tokens) > 1                         and all(t.isalpha() and t.istitle() for t in tokens):
                    rule = "word"
                if rule:
                    index.setdefault(tuple(t.lower() for t in tokens), []).append(Alias(entity, tokens, rule))
        self.entities = entities
        self.index = index
        self.max_tokens = max((len(k) for k in index), default=1)
        self.vendor_tokens = frozenset(k[0] for k, v in index.items()
                                       if len(k) == 1 and any(a.entity.type == "vendor" for a in v))

    def counts(self) -> dict[str, int]:
        out = {t: 0 for t in TYPE_ORDER}
        for entity in self.entities:
            out[entity.type] += 1
        return out

    def lookup(self, name: str) -> list[Entity]:
        tokens = tuple(t.lower() for t in tokenize(name))
        found = {id(a.entity): a.entity for a in self.index.get(tokens, [])}
        return sorted(found.values(), key=lambda e: (TYPE_ORDER.index(e.type), e.id))

    def _accept(self, alias: Alias, tokens: list[str], lows: list[str], gaps: list[str], i: int, size: int) -> bool:
        if alias.tokens[0][0].isupper() and not tokens[i][0].isupper():
            return False
        if alias.rule == "plain":
            return True
        if tuple(tokens[i:i + size]) != alias.tokens:
            return False
        etype = alias.entity.type
        if alias.rule == "acronym" or etype in ("regulator", "country", "product"):
            return True
        after = i + size
        following = tokens[after] if after < len(tokens) and not _BOUNDARY_RE.search(gaps[after]) else None
        cues = VENDOR_CUES if etype == "vendor" else THREAT_CUES
        if following and following[0].isupper() and following.lower() not in cues:
            return False
        if i and lows[i - 1] in self.vendor_tokens and not _BOUNDARY_RE.search(gaps[i]):
            return False
        window = lows[max(0, i - CUE_WINDOW):i] + lows[after:after + CUE_WINDOW]
        if etype == "vendor":
            initial = i == 0 or bool(_BOUNDARY_RE.search(gaps[i]))
            return not initial or any(w in cues for w in window)
        return any(w in cues for w in window)

    def find(self, text: str) -> list[Match]:
        spans = [(m.group(), m.start(), m.end()) for m in TOKEN_RE.finditer(text)]
        tokens = [s[0] for s in spans]
        lows = [t.lower() for t in tokens]
        gaps = [text[spans[i - 1][2] if i else 0:spans[i][1]] for i in range(len(spans))]
        found: list[tuple[Match, Alias]] = []
        i = 0
        while i < len(tokens):
            hit = None
            for size in range(min(self.max_tokens, len(tokens) - i), 0, -1):
                candidates = [a for a in self.index.get(tuple(lows[i:i + size]), ())
                              if self._accept(a, tokens, lows, gaps, i, size)]
                if candidates:
                    best = min(candidates, key=lambda a: (TYPE_ORDER.index(a.entity.type), a.entity.id))
                    start, end = spans[i][1], spans[i + size - 1][2]
                    if "." in tokens[i + size - 1] and text[end:end + 1] == "." and any(
                            n.endswith(".") for n in best.entity.names()):
                        end += 1
                    hit = (Match(start, end, text[start:end], best.entity), best)
                    i += size
                    break
            if hit:
                found.append(hit)
            else:
                i += 1
        vendors = {m.entity.name for m, _ in found if m.entity.type == "vendor"}
        return [m for m, a in found
                if not (a.rule == "word" and m.entity.type == "product" and m.entity.meta.get("vendor") not in vendors)]

    def stale(self, name: str) -> bool:
        cached = self._read_cache(name)
        return cached is None or time.time() - float(cached.get("fetched") or 0) > self.refresh_seconds

    async def _refresh_one(self, http, name: str, url: str, parse, timeout: float | None) -> str:
        cached = self._read_cache(name) or {}
        headers = {"Accept": "application/json, application/zip, */*;q=0.5"}
        if cached.get("entities"):
            if cached.get("etag"):
                headers["If-None-Match"] = cached["etag"]
            if cached.get("last_modified"):
                headers["If-Modified-Since"] = cached["last_modified"]
        fetched = await http.get(url, headers=headers, conditional=False, timeout=timeout)
        if fetched is None:
            self._write_cache(name, {**cached, "fetched": int(time.time())})
            return "unchanged"
        parsed = await asyncio.to_thread(parse, fetched.body)
        if not parsed["entities"]:
            raise FetchError(f"no entities found in {url}")
        self._write_cache(name, {**parsed, "fetched": int(time.time()), "etag": fetched.etag,
                                  "last_modified": fetched.last_modified, "url": url})
        return f"{len(parsed['entities'])} entities"

    async def refresh(self, http, *, force: bool = False) -> dict[str, str]:
        jobs = [("attack", self.cfg.get("attack_url") or ATTACK_URL, parse_attack, ATTACK_TIMEOUT)]
        if self.cfg.get("use_misp", True):
            jobs.append(("misp_actors", self.cfg.get("misp_actors_url") or MISP_ACTORS_URL, parse_misp_actors, None))
        jobs.append(("cwe", self.cfg.get("cwe_url") or CWE_URL, parse_cwe, None))
        status = {}
        for name, url, parse, timeout in jobs:
            if not force and not self.stale(name):
                status[name] = "fresh"
                continue
            try:
                status[name] = await self._refresh_one(http, name, url, parse, timeout)
            except Exception as exc:
                have = "using the cached copy" if self._read_cache(name) else "no cached copy yet"
                status[name] = f"failed ({type(exc).__name__}: {exc}); {have}"
                log.warning("knowledge base refresh of %s failed: %s; %s", name, exc, have)
        if self._read_cache("kev") is None:
            status["kev"] = await self._fetch_kev(http)
        else:
            status["kev"] = "fresh"
        self.status = status
        await asyncio.to_thread(self.load)
        return status

    async def _fetch_kev(self, http) -> str:
        error = None
        for url in KEV_URLS:
            try:
                fetched = await http.get(url, headers={"Accept": "application/json"}, conditional=False)
                return self.update_kev(json.loads(fetched.body).get("vulnerabilities") or [], reload=False)
            except Exception as exc:
                error = exc
        log.warning("knowledge base: KEV vendor list unavailable: %s", error)
        return f"failed ({error}); no cached copy yet"

    def update_kev(self, vulnerabilities: list[dict], *, reload: bool = True) -> str:
        parsed = parse_kev(vulnerabilities)
        if not parsed["vendors"]:
            return "empty"
        previous = self._read_cache("kev") or {}
        if previous.get("vendors") != parsed["vendors"]:
            self._write_cache("kev", {**parsed, "fetched": int(time.time())})
            if reload:
                self.load()
        return f"{len(parsed['vendors'])} vendors"

    def failed(self) -> list[str]:
        return [f"{name}: {state}" for name, state in sorted(self.status.items()) if state.startswith("failed")]
