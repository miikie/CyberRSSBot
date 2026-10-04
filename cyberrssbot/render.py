from __future__ import annotations

from datetime import date

import discord

from . import msrc
from .util import claim_title, clean_title, parse_time, primary_id, truncate

SEVERITY_COLOR = {"CRITICAL": 0xB71C1C, "HIGH": 0xE65100, "MEDIUM": 0xF9A825, "LOW": 0x1565C0}
CHANNEL_COLOR = {"news": 0x5865F2, "research": 0x8E44AD, "advisories": 0x16A085}
KEV_COLOR = 0xD50000


def _pretty(value: str | None) -> str:
    return (value or "").replace("_", " ")


def _join_limit(parts: list[str], sep: str, limit: int = 1024) -> str:
    out = ""
    for part in parts:
        candidate = part if not out else out + sep + part
        if len(candidate) > limit - 2:
            return out + (sep + "…" if out else "…")
        out = candidate
    return out


def vuln_embed(d: dict) -> discord.Embed:
    pid = primary_id(d)
    label = d.get("title")
    if not label and d.get("vendor"):
        label = f"{_pretty(d['vendor']).title()} {_pretty(d.get('product'))}".strip()
    title = f"{pid} — {label}" if label else pid
    if d.get("status") == "Rejected":
        title = "[REJECTED] " + title

    refs = d.get("refs") or {}
    severity = (d.get("severity") or "").upper()
    embed = discord.Embed(
        title=truncate(title, 256),
        url=refs.get("NVD") or next(iter(refs.values()), None),
        description=truncate(d.get("description"), 700),
        color=KEV_COLOR if d.get("kev") else SEVERITY_COLOR.get(severity, 0x607D8B),
    )

    if d.get("cvss") is not None:
        score = f"**{float(d['cvss']):.1f}** {severity.title()}".strip()
        if d.get("cvss_version"):
            score += f" · v{d['cvss_version']}"
    else:
        score = severity.title() if severity else "Not scored yet"
    embed.add_field(name="CVSS", value=score)

    if d.get("epss") is not None:
        embed.add_field(name="EPSS", value=f"{d['epss'] * 100:.1f}% · p{(d.get('epss_pct') or 0) * 100:.0f}")
    else:
        embed.add_field(name="EPSS", value="—")

    kev = d.get("kev")
    if kev:
        value = f"🚨 Added {kev.get('date_added') or '?'}"
        if kev.get("due"):
            value += f"\nFed due date {kev['due']}"
        if (kev.get("ransomware") or "").lower() == "known":
            value += "\nKnown ransomware use"
        embed.add_field(name="CISA KEV", value=value)

    affected = []
    if d.get("vendor"):
        affected.append(f"{_pretty(d['vendor'])} / {_pretty(d.get('product')) or '?'}")
    affected += (d.get("packages") or [])[:6]
    if affected:
        embed.add_field(name="Affected", value=_join_limit(affected, "\n"), inline=False)
    if d.get("cwe"):
        embed.add_field(name="Weakness", value=", ".join(d["cwe"][:4]))
    if refs:
        embed.add_field(name="Sources", value=_join_limit([f"[{k}]({v})" for k, v in refs.items()], " · "),
                        inline=False)
    if d.get("news"):
        lines = [f"• [{truncate(n['title'], 90)}]({n['url']}) — {n['source']}" for n in d["news"][:5]]
        embed.add_field(name="In the news", value=_join_limit(lines, "\n"), inline=False)

    aliases = [a for a in d.get("aliases") or [] if a != pid]
    if aliases:
        embed.set_footer(text="Also tracked as " + ", ".join(aliases[:4]))
    published = parse_time(d.get("published"))
    if published:
        embed.timestamp = published
    return embed


def kev_escalation_embed(d: dict, jump_url: str | None) -> discord.Embed:
    pid = primary_id(d)
    kev = d.get("kev") or {}
    lines = [truncate(kev.get("name") or d.get("title") or "", 200)]
    if (kev.get("ransomware") or "").lower() == "known":
        lines.append("Known ransomware use.")
    if jump_url:
        lines.append(f"[Jump to the original card]({jump_url})")
    return discord.Embed(
        title=truncate(f"🚨 {pid} is now in CISA KEV (actively exploited)", 256),
        url=(d.get("refs") or {}).get("CISA KEV"),
        description="\n".join(l for l in lines if l),
        color=KEV_COLOR,
    )


def story_embed(d: dict) -> discord.Embed:
    summary = d.get("summary") or ""
    if summary.lower().startswith(d["title"].lower()[:60]):
        summary = ""
    title = claim_title(d["claim"]) if d.get("claim") else clean_title(d["title"]) or d["title"]
    embed = discord.Embed(
        title=truncate(title, 256),
        url=d["url"],
        description=truncate(summary, 350),
        color=CHANNEL_COLOR.get(d.get("channel"), 0x5865F2),
    )
    embed.set_author(name=truncate(d["source"], 256))
    if d.get("cves"):
        links = [f"[{c}](https://nvd.nist.gov/vuln/detail/{c})" for c in d["cves"][:8]]
        embed.add_field(name="CVEs", value=_join_limit(links, ", "), inline=False)
    if d.get("also"):
        links = [f"[{a['source']}]({a['url']})" for a in d["also"]]
        embed.add_field(name=f"Also covered by ({len(d['also'])})", value=_join_limit(links, " · "), inline=False)
    published = parse_time(d.get("published"))
    if published:
        embed.timestamp = published
    return embed


MS_COLOR = 0x0078D4


def _cve_lines(cves: list[tuple[str, str]]) -> str:
    return _join_limit([f"[{cve}]({msrc.cve_url(cve)}) — {truncate(title, 110)}" for cve, title in cves], "\n")


def kb_embed(d: dict) -> discord.Embed:
    counts = msrc.kb_counts(d)
    release = d.get("release") or {}
    builds = [msrc.short_build(b) for b in d.get("builds") or []]
    if counts["exploited"]:
        color = KEV_COLOR
    elif counts["critical"]:
        color = SEVERITY_COLOR["HIGH"]
    else:
        color = MS_COLOR
    embed = discord.Embed(title=f"Windows Security update · KB{d['kb']}", url=msrc.kb_url(d["kb"]), color=color)
    embed.add_field(name="Versions covered", value=_join_limit(d.get("versions") or [], "\n") or "—", inline=False)
    embed.add_field(name="OS build" if len(builds) == 1 else "OS builds", value=_join_limit(builds, ", ") or "—")
    embed.add_field(name="Release date", value=release.get("date") or "Not listed yet")
    embed.add_field(name="Release type", value=msrc.release_label(release.get("type"), d.get("subtype")))
    embed.add_field(
        name="Fixes",
        value=(f"**{counts['cves']}** CVE{'' if counts['cves'] == 1 else 's'} · {counts['components']} "
               f"component{'' if counts['components'] == 1 else 's'} · {counts['critical']} Critical · "
               f"{counts['exploited']} exploited · {counts['disclosed']} publicly disclosed"),
        inline=False)
    exploited = sorted((cve, c["title"]) for cve, c in d["cves"].items() if c["exploited"])
    disclosed = sorted((cve, c["title"]) for cve, c in d["cves"].items() if c["disclosed"])
    if exploited:
        embed.add_field(name="🚨 Exploited", value=_cve_lines(exploited), inline=False)
    if disclosed:
        embed.add_field(name="Publicly disclosed", value=_cve_lines(disclosed), inline=False)
    if d.get("supersedes"):
        embed.set_footer(text="Replaces " + ", ".join(f"KB{kb}" for kb in d["supersedes"][:4]))
    published = parse_time(release.get("date"))
    if published:
        embed.timestamp = published
    return embed


def patch_summary_embed(doc_id: str, doc: dict, cards: list[tuple[dict, str | None]]) -> discord.Embed:
    month = msrc.doc_month(doc_id)
    cves: dict[str, dict] = {}
    for data, _ in cards:
        for cve, c in data["cves"].items():
            known = cves.get(cve)
            if known is None or msrc.SEVERITY_RANK.get(c["severity"], 0) > msrc.SEVERITY_RANK.get(known["severity"], 0):
                cves[cve] = c
    critical = sum(1 for c in cves.values() if c["severity"] == "Critical")
    embed = discord.Embed(
        title=truncate(f"Patch Tuesday summary · {month:%B %Y}" if month else f"Patch Tuesday summary · {doc_id}", 256),
        url=msrc.doc_url(doc_id),
        description=truncate(doc.get("title"), 300),
        color=KEV_COLOR if doc.get("exploited") else MS_COLOR,
    )
    embed.add_field(name="Totals", value=(f"**{len(cves)}** CVEs fixed by the tracked Windows updates · "
                                          f"{doc.get('total') or 0} entries in the full release"), inline=False)
    embed.add_field(name="Critical", value=str(critical))
    embed.add_field(name="Exploited", value=str(len(doc.get("exploited") or [])))
    embed.add_field(name="Publicly disclosed", value=str(len(doc.get("disclosed") or [])))
    zero_days = [(e["cve"], e["title"]) for e in doc.get("exploited") or []]
    embed.add_field(name="🚨 Exploited zero-days", value=_cve_lines(zero_days) if zero_days else "None reported",
                    inline=False)
    lines = []
    for data, jump in cards:
        label = f"[KB{data['kb']}]({jump})" if jump else f"KB{data['kb']}"
        lines.append(f"{label} — {truncate(', '.join(data.get('versions') or []), 120)}")
    embed.add_field(name=f"Update cards ({len(cards)})", value=_join_limit(lines, "\n") or "—", inline=False)
    return embed


DIGEST_COLOR = 0x37474F
ENTITY_KINDS = {"group": "Threat actor", "ransomware": "Ransomware group", "malware": "Malware", "tool": "Tool",
                "vendor": "Vendor", "product": "Product", "regulator": "Regulator", "law": "Law",
                "country": "Country"}
ENTITY_SOURCES = {"attack": "MITRE ATT&CK", "misp": "MISP galaxy", "kev": "CISA KEV", "manual": "manual list",
                  "watchlist": "finance watchlist"}


def digest_embed(digest, message: str, index: int) -> discord.Embed:
    embed = discord.Embed(description=message, color=DIGEST_COLOR)
    if index == 0:
        embed.title = truncate(f"Security digest · {digest.edition} edition", 256)
    embed.set_footer(text=truncate(
        f"Window: {digest.window()} · Run {digest.run_id} · {index + 1}/{len(digest.messages)}", 2048))
    return embed


def digest_summary_embed(digest, posted: int) -> discord.Embed:
    stats = digest.stats
    embed = discord.Embed(title=truncate(f"Digest run {digest.run_id}", 256), color=DIGEST_COLOR)
    embed.add_field(name="Window", value=digest.window(), inline=False)
    embed.add_field(name="Messages posted", value=f"{posted} of {len(digest.messages)}")
    embed.add_field(name="Items shown", value=str(stats.get("items", 0)))
    embed.add_field(name="Sources checked", value=f"{stats.get('checked', 0)} of {stats.get('sources', 0)}")
    failed = stats.get("failed") or []
    errors = [f"`{f['id']}`: {truncate(str(f.get('error') or 'unknown error'), 80)}" for f in failed]
    embed.add_field(name=f"Source errors ({len(failed)})", value=_join_limit(errors, "\n") or "None", inline=False)
    embed.add_field(
        name="Suppressed items",
        value=(f"{stats.get('excluded', 0)} dated outside the window · {stats.get('unclassified', 0)} matched no "
               f"section · {stats.get('below_cut', 0)} below the cut"),
        inline=False)
    return embed


def digest_status_embed(*, enabled: bool, channel: str, channel_ok: bool, upcoming: list[tuple[str, float, object]],
                        last: tuple[str, int] | None) -> discord.Embed:
    embed = discord.Embed(title="Digest status", color=DIGEST_COLOR)
    if not enabled:
        state = "Off (`digest.enabled` is false). `/digest now` still works."
    elif not channel_ok:
        state = f"On, but the `{channel}` channel is not set or failed the channel check, so nothing is posted."
    else:
        state = f"On, posting to the `{channel}` channel."
    embed.add_field(name="Scheduled editions", value=state, inline=False)
    if upcoming:
        name, hours, moment = upcoming[0]
        stamp = int(moment.timestamp())
        embed.add_field(name="Next edition" if enabled else "Next edition (if enabled)",
                        value=f"`{name}` ({hours:g}h window) <t:{stamp}:F> · <t:{stamp}:R>", inline=False)
        lines = [f"`{n}` · {h:g}h window · next <t:{int(m.timestamp())}:t>" for n, h, m in upcoming]
        embed.add_field(name=f"Editions ({len(upcoming)})", value=_join_limit(lines, "\n"), inline=False)
    else:
        embed.add_field(name="Editions", value="None configured.", inline=False)
    embed.add_field(name="Last run", value=f"`{last[0]}` · <t:{last[1]}:R>" if last else "No run recorded yet.",
                    inline=False)
    return embed


def channels_embed(health: list[tuple[str, int, str]], overridden=frozenset()) -> discord.Embed:
    lines = []
    for key, channel_id, state in health:
        if state == "unset":
            line = f"⚪ `{key}` not set"
        elif state == "unchecked":
            line = f"⚪ `{key}` → <#{channel_id}> · not checked yet"
        elif state == "ok":
            line = f"🟢 `{key}` → <#{channel_id}>"
        else:
            line = f"🔴 `{key}` → <#{channel_id}> · {state} (posting disabled)"
        lines.append(line + " · set with /channel" if key in overridden else line)
    embed = discord.Embed(title="Channel health", color=0x2B2D31,
                          description=_join_limit(lines, "\n", 4000) or "No channels configured.")
    embed.set_footer(text="Change one with /channel set, undo with /channel reset.")
    return embed


def layout_result_text(result: dict) -> str:
    head = (f"Layout `{result['run_id']}` applied." if result["ok"] else
            f"Layout `{result['run_id']}` stopped partway: {result['error']}")
    lines = [head, "", f"Done ({len(result['applied'])}):"] + [f"• {d}" for d in result["applied"]]
    if result["ok"]:
        problems = result.get("problems") or {}
        lines += ["", "Channel check: " + ("every channel is usable." if not problems else
                                           "; ".join(f"{k}: {', '.join(v)}" for k, v in problems.items()))]
        lines += ["The new key → channel mapping is active now and written to layout-applied.yaml."]
    lines += ["", f"Undo with `/setup rollback run_id:{result['run_id']}`."]
    return "\n".join(lines)


def layout_log_embed(result: dict) -> discord.Embed:
    embed = discord.Embed(title=truncate(f"Server layout {result['run_id']}", 256),
                          color=0x2E7D32 if result["ok"] else 0xC62828,
                          description=_join_limit([f"• {d}" for d in result["applied"]], "\n", 3800) or "No changes.")
    if not result["ok"]:
        embed.add_field(name="Stopped", value=truncate(result["error"], 1000), inline=False)
    embed.set_footer(text=f"Undo: /setup rollback run_id:{result['run_id']}")
    return embed


def routes_embed(rows: list[dict], days: int) -> discord.Embed:
    embed = discord.Embed(title=f"Route preview · last {days} days", color=DIGEST_COLOR,
                          description="How many posted items each route would have moved out of their usual "
                                      "channel. Nothing is changed.")
    for row in rows:
        state = "on" if row["enabled"] else "off"
        target = f"<#{row['target']}>" if row["target"] else "no channel set"
        value = [f"Labels: {', '.join(row['labels'])} · {state} · to {target}",
                 f"Would move **{row['count']}** item{'s' if row['count'] != 1 else ''}"
                 + (f" from {', '.join('`' + k + '`' for k in row['from'])}" if row["from"] else "")]
        value += [f"• {truncate(t, 90)}" for t in row["examples"]]
        embed.add_field(name=row["route"], value=_join_limit(value, "\n"), inline=False)
    if not rows:
        embed.add_field(name="No routes", value="`routing:` is empty in the config.", inline=False)
    return embed


def entity_aliases(entity) -> list[str]:
    seen = {entity.name.casefold(), str(entity.id).casefold()}
    out = []
    for alias in entity.aliases:
        key = alias.strip().casefold()
        if key and key not in seen:
            seen.add(key)
            out.append(alias.strip())
    return out


def entity_embed(entities: list, mentions: list[dict], days: int) -> discord.Embed:
    first = entities[0]
    embed = discord.Embed(title=truncate(first.name, 256), url=first.meta.get("url"), color=DIGEST_COLOR)
    for entity in entities[:4]:
        lines = [f"{ENTITY_KINDS.get(entity.kind, entity.kind)} · {ENTITY_SOURCES.get(entity.source, entity.source)}"
                 + (f" · `{entity.id}`" if entity.source == "attack" else "")]
        if entity.meta.get("vendor"):
            lines.append(f"Vendor: {entity.meta['vendor']}")
        if entity.meta.get("jurisdiction"):
            lines.append(f"Jurisdiction: {entity.meta['jurisdiction']}")
        aliases = entity_aliases(entity)
        if aliases:
            lines.append("Also known as: " + _join_limit(aliases, ", ", 800))
        embed.add_field(name=truncate(f"{entity.name} ({entity.type})", 256), value="\n".join(lines), inline=False)
    lines = [f"• [{truncate(m['title'], 90)}]({m['url']}) — {m['source']}" if m.get("url")
             else f"• {truncate(m['title'], 90)} — {m['source']}" for m in mentions]
    embed.add_field(name=f"Recent items (last {days} days)",
                    value=_join_limit(lines, "\n") or "No items mention it.", inline=False)
    return embed


def status_embeds(sources, states: dict) -> list[discord.Embed]:
    lines = []
    for src in sources:
        st = states.get(src.id, {})
        fails = st.get("fails") or 0
        icon = "🔴" if fails >= 3 else "🟡" if fails else ("🟢" if st.get("last_ok") else "⚪")
        last_ok = f"<t:{st['last_ok']}:R>" if st.get("last_ok") else "never"
        line = f"{icon} `{src.id}` → #{src.channel} · ok {last_ok} · {st.get('items') or 0} items"
        if fails:
            line += f"\n  ↳ {truncate(st.get('last_err'), 90)}"
        lines.append(line)

    embeds, buf = [], ""
    for line in lines:
        if len(buf) + len(line) + 1 > 3900:
            embeds.append(discord.Embed(description=buf, color=0x2B2D31))
            buf = ""
        buf += line + "\n"
    if buf or not embeds:
        embeds.append(discord.Embed(description=buf or "No sources configured.", color=0x2B2D31))
    embeds[0].title = "Feed status"
    return embeds[:10]


FIN_FOOTER = "Data may be delayed. Not financial advice."
UP_COLOR, DOWN_COLOR, FLAT_COLOR = 0x2E7D32, 0xC62828, 0x607D8B
EVENT_COLOR = {"earnings": 0xF9A825, "earnings_date": 0xFBC02D, "mna": 0x6A1B9A, "leadership": 0x1565C0,
               "guidance": 0x00838F, "buyback": 0x2E7D32, "offering": 0x5D4037, "periodic": 0x455A64,
               "stake": 0xAD1457, "insider": 0x78909C, "restructuring": 0xBF360C}
EARNINGS_HOUR = {"bmo": "Before open", "amc": "After close", "dmh": "During market"}
EVENT_NAMES = {
    "earnings": "Earnings", "earnings_date": "Earnings date", "mna": "M&A", "guidance": "Guidance",
    "leadership": "Leadership", "buyback": "Buyback", "offering": "Offering", "periodic": "Periodic report",
    "stake": "Ownership stake", "insider": "Insider trade", "vote": "Shareholder vote",
    "restructuring": "Restructuring", "listing": "Listing", "other": "Announcement",
}


def _money(value) -> str:
    return f"${float(value):,.2f}" if value is not None else "—"


def _big(value) -> str:
    if value is None:
        return "—"
    value = float(value)
    for unit, size in (("T", 1e12), ("B", 1e9), ("M", 1e6)):
        if abs(value) >= size:
            return f"${value / size:.2f}{unit}"
    return f"${value:,.0f}"


def _move_color(dp) -> int:
    if dp is None or abs(float(dp)) < 0.005:
        return FLAT_COLOR
    return UP_COLOR if float(dp) > 0 else DOWN_COLOR


def finance_item_embed(d: dict) -> discord.Embed:
    summary = d.get("summary") or ""
    if summary.lower().startswith(d["title"].lower()[:60]):
        summary = ""
    embed = discord.Embed(
        title=truncate(f"{' · '.join(d['tickers'])} — {d['title']}", 256),
        url=d["url"],
        description=truncate(summary, 350),
        color=EVENT_COLOR.get(d.get("event"), 0x5865F2),
    )
    embed.set_author(name=truncate(f"{EVENT_NAMES.get(d.get('event'), 'Announcement')} · {d['source']}", 256))
    filings = [f for f in d.get("filings") or [] if f["url"] != d["url"]]
    if filings:
        embed.add_field(name="Filing", value=_join_limit([f"[{f['label']}]({f['url']})" for f in filings], "\n"),
                        inline=False)
    if d.get("also"):
        links = [f"[{a['source']}]({a['url']})" for a in d["also"]]
        embed.add_field(name=f"Also covered by ({len(d['also'])})", value=_join_limit(links, " · "), inline=False)
    embed.set_footer(text=FIN_FOOTER)
    published = parse_time(d.get("published"))
    if published:
        embed.timestamp = published
    return embed


def event_link(ev: dict, jump_url=None) -> str:
    refs = ev["source_refs"]
    post = refs.get("message") or refs.get("post")
    target = (jump_url(*post) if post and jump_url else None) or refs.get("filing") or refs.get("url")
    label = ev["type"]
    detail = ev["payload"].get("title") or ev["payload"].get("victim") or ev["payload"].get("name") or ""
    text = f"`{label}`" + (f" {truncate(detail, 70)}" if detail else "")
    return f"{text} · [link]({target})" if target else text


def move_alert_embed(symbol: str, name: str, q: dict, level: int, pct: float, context: dict | None,
                     explanation: dict | None = None, jump_url=None, sector_dp: float | None = None) -> discord.Embed:
    dp = float(q["dp"])
    arrow = "📈" if dp > 0 else "📉"
    embed = discord.Embed(
        title=truncate(f"{arrow} {symbol} {'up' if dp > 0 else 'down'} {abs(dp):.1f}% — {name}", 256),
        description=f"Moved past {level * pct:g}% from the previous close." if level == 2 else None,
        color=_move_color(dp),
    )
    embed.add_field(name="Price", value=_money(q.get("c")))
    embed.add_field(name="Change", value=f"{float(q.get('d') or 0):+.2f} ({dp:+.2f}%)")
    embed.add_field(name="Previous close", value=_money(q.get("pc")))
    if q.get("l") and q.get("h"):
        embed.add_field(name="Day range", value=f"{_money(q['l'])} – {_money(q['h'])}")
    if context:
        embed.add_field(name="Related", value=f"[{truncate(context['title'], 150)}]({context['url']}) — {context['source']}",
                        inline=False)
    if explanation:
        sector = f"CIBR {sector_dp:+.2f}%" if sector_dp is not None else "CIBR not available"
        if explanation["classification"] == "with sector":
            kind = f"Observed moving with the sector ({sector})"
        else:
            kind = f"Idiosyncratic: differs from the sector by more than 40% of the move ({sector})"
        embed.add_field(name="Move", value=kind, inline=False)
        lines = [f"• {event_link(ev, jump_url)}" for ev in explanation["catalysts"]]
        embed.add_field(name="Recorded events, last 72 hours",
                        value=_join_limit(lines, "\n") or "None recorded. Logged as an unexplained move.", inline=False)
    embed.set_footer(text=FIN_FOOTER)
    return embed


def close_summary_embed(day, quotes: dict[str, dict], watch, unexplained: list | None = None) -> discord.Embed:
    companies = sorted(((s, q) for s, q in quotes.items() if s in watch.companies),
                       key=lambda sq: float(sq[1].get("dp") or 0), reverse=True)
    lines = [f"{s:<5} {float(q['c']):>9.2f} {float(q.get('dp') or 0):>+7.2f}%" for s, q in companies]
    avg = sum(float(q.get("dp") or 0) for _, q in companies) / len(companies) if companies else 0
    embed = discord.Embed(
        title=f"Cyber stocks at the close — {day:%a %b %d, %Y}",
        description="```\n" + "\n".join(lines) + "\n```" if lines else "No quotes.",
        color=_move_color(avg),
    )
    etfs = [f"**{s}** {float(q.get('dp') or 0):+.2f}%" for s, q in quotes.items() if s in watch.benchmarks]
    if etfs:
        embed.add_field(name="ETF benchmarks", value=" · ".join(etfs), inline=False)
    if companies:
        top, bottom = companies[0], companies[-1]
        embed.add_field(name="Biggest gainer", value=f"{top[0]} {float(top[1].get('dp') or 0):+.2f}%")
        embed.add_field(name="Biggest loser", value=f"{bottom[0]} {float(bottom[1].get('dp') or 0):+.2f}%")
        embed.add_field(name="Average", value=f"{avg:+.2f}%")
    if unexplained:
        embed.add_field(name="Unexplained moves", value=", ".join(f"{s} {dp:+.2f}%" for s, dp in unexplained),
                        inline=False)
    embed.set_footer(text=FIN_FOOTER)
    return embed


def earnings_embed(rows: list[dict], watch, title: str, empty: str = "Nothing scheduled.") -> discord.Embed:
    lines = []
    for r in rows:
        when = date.fromisoformat(r["date"]).strftime("%a %b %d")
        parts = [f"**{when}**", f"**{r['symbol']}** {watch.name(r['symbol'])}",
                 EARNINGS_HOUR.get((r.get("hour") or "").lower(), "Time TBA")]
        if r.get("epsEstimate") is not None:
            parts.append(f"EPS est {float(r['epsEstimate']):.2f}")
        if r.get("revenueEstimate"):
            parts.append(f"Rev est {_big(r['revenueEstimate'])}")
        lines.append(" · ".join(parts))
    embed = discord.Embed(title=title, description=_join_limit(lines, "\n", 4000) if lines else empty,
                          color=EVENT_COLOR["earnings"])
    embed.set_footer(text=FIN_FOOTER)
    return embed


def stock_embed(symbol: str, name: str, quote: tuple[dict, int] | None, items: list[dict]) -> discord.Embed:
    q, ts = quote if quote else ({}, None)
    dp = q.get("dp")
    title = f"{symbol} — {name}"
    if q.get("c"):
        title += f" · {_money(q['c'])} ({float(dp or 0):+.2f}%)"
    embed = discord.Embed(title=truncate(title, 256), color=_move_color(dp))
    if q.get("c"):
        embed.add_field(name="Change", value=f"{float(q.get('d') or 0):+.2f}")
        embed.add_field(name="Previous close", value=_money(q.get("pc")))
        embed.add_field(name="Day range", value=f"{_money(q.get('l'))} – {_money(q.get('h'))}")
        if ts:
            embed.add_field(name="Quote time", value=f"<t:{int(q.get('t') or ts)}:R>")
    else:
        embed.description = "No quote available yet."
    if items:
        lines = [f"• [{truncate(i['data']['title'], 90)}]({i['data']['url']}) — <t:{i['ts']}:d>" for i in items]
        embed.add_field(name="Recent finance items", value=_join_limit(lines, "\n"), inline=False)
    embed.set_footer(text=FIN_FOOTER)
    return embed


INCIDENT_COLOR = 0xB71C1C
TIMING_TEXT = {"pre": "before the open", "intraday": "during the session", "post": "after the close",
               "closed": "while the market was closed"}
INCIDENT_TITLES = {"sec.8k.1_05": "8-K Item 1.05 · material cybersecurity incident",
                   "sec.8k.1_05_amendment": "8-K/A · Item 1.05 update",
                   "sec.8k.8_01_cyber": "8-K Item 8.01 · cyber disclosure"}


def _who(ev: dict) -> str:
    name = ev.get("company") or "Unknown filer"
    return f"{name} ({ev['ticker']})" if ev.get("ticker") else name


def _when(ev: dict) -> str:
    occurred = parse_time(ev["occurred_at"])
    stamp = f"<t:{int(occurred.timestamp())}:f>" if occurred else ev["occurred_at"]
    return (f"{stamp} · {TIMING_TEXT.get(ev['session_timing'], ev['session_timing'])} · "
            f"session {ev['effective_session']}")


def incident_embed(ev: dict, original_jump: str | None = None, history: str | None = None) -> discord.Embed:
    from . import incidents
    payload, refs = ev["payload"], ev["source_refs"]
    embed = discord.Embed(title=truncate(f"{_who(ev)} · {INCIDENT_TITLES.get(ev['type'], ev['type'])}", 256),
                          url=refs.get("filing") or refs.get("document"), color=INCIDENT_COLOR,
                          description=history)
    listing = ev["ticker"] or "No listed equity"
    if payload.get("exchange"):
        listing += f" · {payload['exchange']}"
    embed.add_field(name="Ticker", value=listing)
    embed.add_field(name="Form", value=f"{payload.get('form', '8-K')} · items {', '.join(payload.get('items') or [])}")
    embed.add_field(name="Filed", value=_when(ev), inline=False)
    found = incidents.badges(payload.get("features") or {}, payload.get("amendments") or 0)
    embed.add_field(name="Disclosed", value=" · ".join(f"`{b}`" for b in found) or "No severity markers found",
                    inline=False)
    if payload.get("keywords"):
        embed.add_field(name="Matched", value=", ".join(payload["keywords"][:6]), inline=False)
    links = [f"[Filing]({refs['filing']})"] if refs.get("filing") else []
    if refs.get("document") and refs.get("document") != refs.get("filing"):
        links.append(f"[Document]({refs['document']})")
    if original_jump:
        links.append(f"[Original 1.05 card]({original_jump})")
    if links:
        embed.add_field(name="Links", value=" · ".join(links), inline=False)
    embed.set_footer(text=FIN_FOOTER)
    return embed


def compact_incident_embed(ev: dict, text: str, jump: str | None) -> discord.Embed:
    label = "Ransomware claim" if ev["type"] == "ransomware.claim.public" else "Breach coverage"
    embed = discord.Embed(title=truncate(f"{label} · {ev['ticker']}", 256), color=INCIDENT_COLOR,
                          description=truncate(text, 300))
    match = ev["payload"].get("match")
    embed.add_field(name="Company", value=truncate(f"{ev.get('company') or ev['ticker']}"
                                                   f"{' (name match, check it)' if match == 'fuzzy' else ''}", 1024))
    if jump:
        embed.add_field(name="Original post", value=f"[Jump]({jump})")
    embed.set_footer(text=FIN_FOOTER)
    return embed


def _pct(value: float | None) -> str:
    return "—" if value is None else f"{value * 100:+.2f}%"


def study_embed(result: dict, days: int, ticker: str | None = None) -> discord.Embed:
    from .events import EVENT_TYPES
    title = f"Event study · {result['type']} · CAR[0,+{days}]" + (f" · {ticker}" if ticker else "")
    embed = discord.Embed(title=truncate(title, 256), color=DIGEST_COLOR, description=(
        f"{EVENT_TYPES.get(result['type'], result['type'])}. Market-adjusted abnormal return: the stock's return "
        "minus CIBR (watchlist and exposure tickers) or SPY, summed over the window. Observed historically; "
        "not a forecast."))
    for label, name in (("main", "Before the open, after the close or market closed"),
                        ("intraday", "Filed during the session (reported separately)")):
        part = result[label]
        s = part["summary"]
        if not s.n:
            value = "No events with prices for this window."
        else:
            value = (f"n = {s.n}{' · **insufficient data** (n < 20)' if s.insufficient else ''}\n"
                     f"Mean {_pct(s.mean)} · median {_pct(s.median)}\n"
                     f"95% CI of the mean {_pct(s.ci[0])} to {_pct(s.ci[1])}"
                     + (f" · t = {s.t_stat:.2f}" if s.t_stat is not None else "") + "\n"
                     f"Negative {s.share_negative:.0%} · positive {s.share_positive:.0%}")
        extra = []
        if part["overlap_dropped"]:
            extra.append(f"{part['overlap_dropped']} overlapping")
        if part["skipped"]:
            extra.append(f"{part['skipped']} without prices")
        if part["pending"]:
            extra.append(f"{part['pending']} window not complete yet")
        if extra:
            value += "\nNot counted: " + ", ".join(extra)
        embed.add_field(name=name, value=value, inline=False)
    embed.set_footer(text=FIN_FOOTER)
    return embed


def events_embed(ticker: str, days: int, rows: list[dict], jump_url) -> discord.Embed:
    lines = []
    for ev in reversed(rows):
        refs = ev["source_refs"]
        link = refs.get("filing") or refs.get("url")
        post = refs.get("message") or refs.get("post")
        jump = jump_url(*post) if post else None
        label = ev["type"]
        detail = ev["payload"].get("title") or ev["payload"].get("victim") or ev["payload"].get("name") or ""
        line = f"• {ev['effective_session']} · `{label}`" + (f" · {truncate(detail, 70)}" if detail else "")
        targets = [f"[source]({link})"] if link else []
        if jump:
            targets.append(f"[post]({jump})")
        lines.append(line + (" · " + " · ".join(targets) if targets else ""))
    embed = discord.Embed(title=truncate(f"{ticker} · events in the last {days} days", 256), color=DIGEST_COLOR,
                          description=_join_limit(lines, "\n", 4000) or "No recorded events.")
    embed.set_footer(text=FIN_FOOTER)
    return embed


SIGNAL_COLOR = 0x6A1B9A


def _contributors(top: list[dict]) -> str:
    lines = []
    for c in top:
        title = truncate(c.get("title") or "", 80)
        lines.append(f"• [{title}]({c['url']})" if c.get("url") else f"• {title}")
    return _join_limit(lines, "\n") or "—"


def pressure_spike_embed(ev: dict) -> discord.Embed:
    p = ev["payload"]
    embed = discord.Embed(title=truncate(f"Vulnerability pressure spike · {ev['ticker']}", 256), color=SIGNAL_COLOR,
                          description=(f"Observed pressure score {p['score']:.1f}, {p['z']:.1f} standard deviations above "
                                       f"this ticker's own history, from {p['items']} distinct items in the last 30 days. "
                                       "A signal, not a forecast."))
    embed.add_field(name="Top contributors", value=_contributors(p.get("top") or []), inline=False)
    embed.set_footer(text=FIN_FOOTER)
    return embed


def pressure_table_embed(rows: list[tuple[str, dict]], day, top: int = 10) -> discord.Embed:
    lines = []
    for ticker, p in rows[:top]:
        z = f"{p['z']:+.1f}" if p["z"] is not None else "n/a"
        lines.append(f"**{ticker}** · score {p['score']:.1f} · z {z} · {p['items']} item{'s' if p['items'] != 1 else ''}")
        for c in p["top"]:
            lines.append(f"  ↳ [{truncate(c.title, 70)}]({c.url})" if c.url else f"  ↳ {truncate(c.title, 70)}")
    embed = discord.Embed(title=f"Vendor vulnerability pressure · week of {day:%b %d, %Y}", color=SIGNAL_COLOR,
                          description=_join_limit(lines, "\n", 4000) or "No vulnerability pressure recorded.")
    embed.add_field(name="How to read it", inline=False, value=(
        "30-day score: KEV entries 5, exploited news 3, CVSS 9+ CVEs 1, plus 0.5 per covering outlet, halving every "
        "14 days. z compares it with the ticker's own last year; n/a means under 90 days of history."))
    embed.set_footer(text=FIN_FOOTER)
    return embed


def insider_embed(ev: dict) -> discord.Embed:
    p = ev["payload"]
    if ev["type"] == "insider.open_buy":
        title = f"Insider open-market purchase · {ev['ticker']}"
        lines = [f"{p.get('owner')} ({p.get('role') or 'insider'}) bought {p.get('shares') or 0:,.0f} shares"
                 + (f" at about ${p['price']:,.2f}" if p.get("price") else "") + f", ${p.get('value') or 0:,.0f} in total.",
                 "Not reported as part of a 10b5-1 trading plan."]
    else:
        title = f"Insider selling cluster · {ev['ticker']}"
        lines = [f"{len(p.get('owners') or [])} insiders sold outside 10b5-1 plans between {p.get('start')} and "
                 f"{p.get('end')}: {', '.join(p.get('names') or [])}.",
                 f"{p.get('sales')} sale{'s' if p.get('sales') != 1 else ''}, ${p.get('value') or 0:,.0f} in total."]
    embed = discord.Embed(title=truncate(title, 256), url=ev["source_refs"].get("filing"), color=SIGNAL_COLOR,
                          description="\n".join(lines))
    embed.set_footer(text=FIN_FOOTER)
    return embed


def _p(value) -> str:
    return "—" if value is None else f"{value * 100:+.2f}%"


def dossier_embeds(d: dict, jump_url=None, compact: bool = False) -> list[discord.Embed]:
    head = discord.Embed(title=truncate(f"Dossier · {d['ticker']} — {d['name']}", 256), color=SIGNAL_COLOR,
                         description=f"As of {d['as_of']}. Everything here is observed history, not a forecast.")
    nxt = d.get("next_earnings")
    if nxt:
        parts = [f"**{nxt['date']}** · {EARNINGS_HOUR.get((nxt.get('hour') or '').lower(), 'time TBA')}"]
        if nxt.get("epsEstimate") is not None:
            parts.append(f"EPS est {float(nxt['epsEstimate']):.2f}")
        if nxt.get("revenueEstimate"):
            parts.append(f"revenue est {_big(nxt['revenueEstimate'])}")
        head.add_field(name="Next earnings", value=" · ".join(parts), inline=False)
    else:
        head.add_field(name="Next earnings", value="No date in the calendar.", inline=False)
    perf = []
    for days in (30, 90):
        p = d["performance"].get(days)
        if p:
            perf.append(f"{days} days: {d['ticker']} {_p(p['stock'])} vs CIBR {_p(p['bench'])} ({_p(p['relative'])} relative)")
    head.add_field(name="Price vs CIBR", value="\n".join(perf) or "No prices yet.", inline=False)
    pr = d.get("pressure")
    if pr:
        z = f"{pr['z']:+.1f}" if pr["z"] is not None else "n/a"
        top = "; ".join(truncate(c.title, 60) for c in pr["top"])
        head.add_field(name="Vulnerability pressure", value=f"score {pr['score']:.1f} · z {z} · {pr['items']} items"
                       + (f"\n{top}" if top else ""), inline=False)
    else:
        head.add_field(name="Vulnerability pressure", value="No contributions in the last 30 days.", inline=False)
    if compact:
        lines = [f"{r['session']}: CAR[0,+1] {_p(r['car_0_1'])} · CAR[0,+5] {_p(r['car_0_5'])}" for r in d["reactions"][:4]]
        head.add_field(name="Last earnings reactions", value="\n".join(lines) or "None recorded.", inline=False)
        head.set_footer(text=FIN_FOOTER)
        return [head]
    head.set_footer(text=FIN_FOOTER)

    hist = discord.Embed(title="Earnings history", color=SIGNAL_COLOR)
    lines = [f"`{r['session']}` CAR[0,+1] {_p(r['car_0_1'])} · CAR[0,+5] {_p(r['car_0_5'])}"
             + (f" · tone {r['tone']:+.2f}" if r["tone"] is not None else "")
             + (f" · [release]({r['link']})" if r.get("link") else "") for r in d["reactions"]]
    hist.description = _join_limit(lines, "\n", 1500) or "No earnings reports recorded."
    tones = [f"{r['tone']:+.2f}" for r in reversed(d["tone"])]
    hist.add_field(name="Tone, oldest to newest", value=" → ".join(tones) or "No scored releases.", inline=False)
    own = [f"• {e['effective_session']} `{e['type']}` " + truncate(str(e["payload"].get("owner") or
           ", ".join(e["payload"].get("names") or []) or e["payload"].get("form") or ""), 70) for e in d["ownership"]]
    hist.add_field(name="Insiders and ownership, 90 days", value=_join_limit(own, "\n", 900) or "None.", inline=False)
    hist.set_footer(text=FIN_FOOTER)

    events = discord.Embed(title="Events, last 90 days", color=SIGNAL_COLOR)
    events.description = _join_limit([f"• {e['effective_session']} " + event_link(e, jump_url)
                                       for e in reversed(d["timeline"])], "\n", 1500) or "No recorded events."
    rows = []
    for e in d["evidence"]:
        ci = f"{_p(e['ci'][0])} to {_p(e['ci'][1])}" if e["ci"] else "—"
        rows.append(f"`{e['type']}` n={e['n']} · mean {_p(e['mean'])} · median {_p(e['median'])} · CI {ci}"
                    + (" · insufficient data" if e["insufficient"] else ""))
    events.add_field(name="Evidence: CAR[0,+5] after each event type, all tickers",
                     value=_join_limit(rows, "\n", 1000) or "—", inline=False)
    events.set_footer(text=FIN_FOOTER)
    return [head, hist, events]


def paper_line(trade: dict, kind: str, ev: dict | None, jump: str | None) -> str:
    what = f"`{ev['type']}`" if ev else "event"
    link = f" ([trigger]({jump}))" if jump else ""
    side = trade["side"]
    if kind == "entry":
        return (f"📝 Paper {'short' if side == 'short' else 'long'} **{trade['ticker']}** opened at "
                f"${trade['entry_price']:,.2f} on {trade['entry_date']} · rule `{trade['rule']}` · {what}{link} · "
                "simulated, no real order")
    return (f"📝 Paper {side} **{trade['ticker']}** closed at ${trade['exit_price']:,.2f} on {trade['exit_date']} "
            f"({trade['exit_reason']}) · {_p(trade['ret'])} · ${trade['pnl']:,.2f} · rule `{trade['rule']}`{link}")


def paper_stats_text(s: dict) -> str:
    if not s.get("closed"):
        return f"{s['trades']} trades, none closed yet."
    out = (f"{s['closed']} closed, {s['open']} open · win rate {s['win_rate']:.0%} · average {_p(s['avg_return'])} · "
           f"P&L ${s['total_pnl']:,.0f} · max drawdown {_p(s['max_drawdown'])}")
    if s.get("benchmark_avg_return") is not None:
        out += f"\nBenchmark held over the same periods: average {_p(s['benchmark_avg_return'])}, " \
               f"${s['benchmark_total_pnl']:,.0f} on the same capital"
    return out


def paper_embed(title: str, rows: list[tuple[str, str]], note: str | None = None) -> discord.Embed:
    embed = discord.Embed(title=truncate(title, 256), color=SIGNAL_COLOR, description=note)
    for name, value in rows[:24]:
        embed.add_field(name=truncate(name, 256), value=truncate(value, 1024), inline=False)
    embed.set_footer(text="Simulated paper trading. No orders are placed. Short borrow costs are ignored. " + FIN_FOOTER)
    return embed


def report_embeds(text: str, title: str) -> list[discord.Embed]:
    chunks, buf = [], ""
    for line in text.split("\n"):
        if buf and len(buf) + len(line) + 1 > 3800:
            chunks.append(buf)
            buf = ""
        buf = f"{buf}\n{line}" if buf else line
    if buf:
        chunks.append(buf)
    embeds = []
    for i, chunk in enumerate(chunks):
        e = discord.Embed(description=chunk, color=SIGNAL_COLOR, title=title if i == 0 else None)
        e.set_footer(text=FIN_FOOTER)
        embeds.append(e)
    return embeds
