from __future__ import annotations

from datetime import date

import discord

from . import msrc
from .util import parse_time, primary_id, truncate

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
    embed = discord.Embed(
        title=truncate(d["title"], 256),
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
        if entity.aliases:
            lines.append("Also known as: " + _join_limit(entity.aliases, ", ", 800))
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


def move_alert_embed(symbol: str, name: str, q: dict, level: int, pct: float, context: dict | None) -> discord.Embed:
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
    embed.set_footer(text=FIN_FOOTER)
    return embed


def close_summary_embed(day, quotes: dict[str, dict], watch) -> discord.Embed:
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
