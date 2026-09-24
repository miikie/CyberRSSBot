from __future__ import annotations

from datetime import date

import discord

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
