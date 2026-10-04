# CyberRSSBot

A Discord bot that aggregates cybersecurity news, advisories, threat research and vulnerability intelligence from 54 sources, tracks publicly traded cybersecurity companies, routes everything to topic channels and makes sure every event shows up **once**.

Vulnerabilities reported by NVD, GitHub, MSRC, CISA KEV and FIRST EPSS are merged into a single card per CVE that is edited in place as new information arrives. News stories covered by several outlets are posted once, with the other outlets listed under it.

> This repository is a public showcase of a private project. It is not a product and is not licensed for use, modification or redistribution. See [License](#license).

## Contents

- [Features](#features)
- [Channels](#channels)
- [Sources](#sources)
- [Microsoft security updates](#microsoft-security-updates)
- [Intelligence digest](#intelligence-digest)
- [Cyber-financials](#cyber-financials)
- [How deduplication works](#how-deduplication-works)
- [Rate limiting](#rate-limiting)
- [Slash commands](#slash-commands)
- [Built with](#built-with)
- [Project layout](#project-layout)
- [License](#license)

## Features

- **One card per vulnerability.** CVE and GHSA ids resolve to a single record through an alias table. CVSS, EPSS, KEV status, affected packages, CWEs and source links are merged into it.
- **Edit, don't repost.** Later information edits the existing Discord message. The only extra message for an already-posted vulnerability is a 🚨 escalation when it lands in CISA KEV.
- **Cross-outlet story clustering.** Articles about the same event are grouped; the first is posted and later ones become an *Also covered by* line. Templated feeds, such as leak-site trackers, opt out so that similar-looking titles are never merged.
- **Topic routing.** Every source posts to its own topic channel.
- **Signal over volume.** Vulnerabilities are filtered by CVSS, EPSS, KEV and a vendor watchlist. High-volume CNAs and WordPress plugin noise are muted.
- **Controlled first run.** A new source records its backlog without posting it, optionally posting only the last few hours so channels start populated without being flooded.
- **Polite fetching.** Per-host pacing, ETag / Last-Modified conditional requests, `Retry-After` support and exponential backoff per source.
- **Upgrades in place.** New settings and sources are merged into an existing configuration without touching the values already there, so an update is a single installer run.
- **Self-monitoring.** `/status` shows the health of every source, and repeated failures and recoveries are reported to a log channel. At startup every configured channel is checked for existence and permissions; a channel that fails is reported and skipped instead of crashing the bot. Channels can be reassigned from Discord with `/channel set`, without editing the config file or restarting.
- **Scraper for feedless sites.** Any page can become a source with a CSS selector.
- **Windows update tracking.** One card per Windows KB on Patch Tuesday, with a TSV of every CVE it fixes, edited in place when Microsoft revises the release.
- **Deterministic digests.** Scheduled summaries built by rules from public reference data, with a coverage section that says what was and wasn't checked.
- **Cyber-financials.** SEC filings, press releases, a daily close summary, big-move alerts and an earnings calendar for a watchlist of security stocks.

## Channels

Channels are grouped into categories. Each row is one channel; the keys are the names sources and features post to.

| Category | Channel | Contents |
|---|---|---|
| Overview | digests | Scheduled intelligence digests |
| Vulnerabilities | exploited-in-wild | New CISA KEV entries, plus an escalation when an already-posted CVE is added to KEV |
| Vulnerabilities | cves | One card per CVE / GHSA, merged from NVD, GitHub Advisories, MSRC, KEV and EPSS |
| Vulnerabilities | windows | One card per Windows security update (KB), revision notes and the monthly Patch Tuesday summary |
| Vulnerabilities | advisories | Government CERTs and vendor PSIRTs |
| Threat Intel | threat-intel | Vendor threat research, malware analysis, DFIR write-ups and exploit research |
| Incidents | breaches-ransomware | Breach reports, breach corpora and ransomware leak-site claims |
| News & Policy | articles | Security journalism and law-enforcement press releases |
| News & Policy | supply-chain-policy | Targets for the optional supply-chain and privacy-law routes |
| Cyber-Finance | cyber-markets | Press releases, investor relations and newswire items for the watchlist |
| Cyber-Finance | market-tape | The daily close summary and big-move alerts with likely catalysts |
| Cyber-Finance | sec-filings | Watchlist SEC filings, insider open-market purchases and insider selling clusters |
| Cyber-Finance | incident-disclosures | Market-wide 8-K Item 1.05 incidents and Item 8.01 cyber disclosures, plus compact cards when a leak-site claim or a widely covered breach names a listed company |
| Cyber-Finance | earnings | The earnings calendar and same-day reminders |
| Cyber-Finance | signals | Vendor vulnerability pressure spikes and the weekly pressure ranking |
| Admin (private) | bot-log | Source failures and recoveries, channel checks, digest and layout runs |

### Server layout

`/setup layout` organises the server into this layout. It shows the full plan first: categories and channels to create, channels to adopt, rename and move, channels to retire, permission changes and the final key-to-channel mapping. Nothing changes until an administrator presses **Apply**.

- **Existing channels are adopted by ID.** A layout channel takes over the channel its keys already post to; channels are never matched by name.
- **Nothing is deleted.** Channels the layout no longer uses move to a read-only Archive category with their history.
- **Unrelated channels are left alone.** Channels that no key posts to are not moved, renamed or changed.
- **Feeds are read-only.** Feed channels are read-only for members, the admin category is hidden, and the bot always keeps its own access.
- **Changes take effect immediately.** The new mapping applies without a restart, and the run is logged.
- **Everything can be undone.** A snapshot taken before the changes lets `/setup rollback` restore names, categories, order and permissions.

`/setup routes` shows how many recent items each optional route would move out of its usual channel, before any route is turned on.

## Sources

| Channel | Sources |
|---|---|
| KEV / CVEs | CISA KEV, NVD, GitHub Advisory Database, FIRST EPSS, MSRC |
| Advisories | CERT-EU, NCSC UK, Canadian Centre for Cyber Security, Cisco PSIRT, Fortinet PSIRT, Palo Alto Networks |
| Articles | BleepingComputer, The Hacker News, The Record, SecurityWeek, Krebs on Security, Dark Reading, CyberScoop, Ars Technica, The Register, Schneier on Security |
| Threat intel | Cisco Talos, ESET Research, Unit 42, Microsoft Security, Google Threat Intelligence, Kaspersky Securelist, Check Point Research, Sophos X-Ops, watchTowr Labs, Exploit-DB |
| DFIR | The DFIR Report, SANS Internet Storm Center |
| Data breaches | DataBreaches.net, Have I Been Pwned |
| Ransomware | ransomware.live |
| Malware | ANY.RUN, Malware Traffic Analysis, Malpedia, Malwarebytes Labs |
| Finance | SEC EDGAR (watchlist filings, the market-wide latest-filings feed and full-text search), Yahoo daily prices, Finnhub, Cloudflare and Gen Digital investor relations, GlobeNewswire, Business Wire |
| Microsoft | MSRC CVRF release documents, Windows release information on Microsoft Learn |
| Law enforcement | US Department of Justice, Europol |
| Reference data | MITRE ATT&CK, MITRE CWE, MISP galaxy, CISA KEV |

## Microsoft security updates

The Microsoft channel follows Windows security updates through the [MSRC CVRF API](https://api.msrc.microsoft.com/cvrf/v3.0/updates). Each monthly release document is turned into an index of KBs, and every KB that applies to a tracked product gets one card.

### What gets posted

| Post | When |
|---|---|
| **Update card** | Once per KB, when it first appears in a release document. Patch Tuesday updates, out-of-band updates and servicing stack updates all get one |
| **Revision note** | When Microsoft revises a release and a posted KB changes: one line such as *KB5124008 revised: 3 CVEs added, CVE-2026-12345 now marked exploited*, linking to the original card |
| **Patch Tuesday summary** | Once per monthly release, after its cards |

A card is titled *Windows Security update · KB5124008* and links to the KB's support page. It shows the Windows versions covered, the OS builds, the release date and type (Patch Tuesday, out-of-band or servicing stack update), and how many CVEs, components, Critical fixes, exploited and publicly disclosed vulnerabilities the update contains. Exploited and publicly disclosed CVEs are listed by name.

Every card carries an attachment, `KB<number>-security-fixes.tsv`, with one row per CVE: CVE, title, component, severity, impact, CVSS, exploited, publicly disclosed, affected products and fixed build.

Cards are never reposted. When a release is revised the card is edited in place and its attachment is replaced. The summary gives the number of CVEs fixed by the tracked updates, the Critical count, the exploited zero-days with links, and links to the month's cards.

### Scope and schedule

Only products on an allowlist are tracked: by default Windows 11, Windows 10 and Windows Server 2019, 2022 and 2025. A product is matched by the start of its name, so .NET Framework and Office updates stay out unless they are added. September 2026 produced ten cards.

The release index is checked every 3 hours, and every 30 minutes on Patch Tuesday and the day after. A monthly document is downloaded again only when its release date changes. OS builds and fixed CVEs come from MSRC; release dates and types come from the Windows release information pages on Microsoft Learn. As with every other source, the first run records the existing updates without posting them.

### Links to CVE cards

When a CVE that already has a card is fixed by a tracked KB, a *Fixed in KB…* link is added to that card. The tracker does not create CVE cards of its own, and an exploited CVE is still escalated only when it is added to CISA KEV. An optional role can be mentioned on each new update card.

## Intelligence digest

A rule-based digest that summarises what the bot collected over a time window. It uses no language model and no paid service: entities come from public reference lists, topics and scores from fixed rules, and the same inputs always produce the same text.

### What a digest contains

Each digest covers one window, for example the last 6 hours, and shows the window and a run id. Sections appear in a fixed order: Exploited in the wild, Vulnerabilities & patches, Breaches & ransomware, Threat actors, Malware, Supply chain, Law enforcement, Policy & law and Markets. Each section lists its top items by signal score.

An item is a cleaned headline linking to the source, one sentence quoted from the source's own feed summary with the extracted names and figures in bold, the outlet it came from, and links to other outlets that covered the same story. At most one sentence of about 40 words is quoted per source, always attributed and linked. Items are referenced, not reposted: the original post stays in its own channel.

Several CVEs for the same product are folded into one item, such as *ZITADEL: 5 authentication flaws, CVSS up to 9.8, fixed in 3.4.15 / 4.17.3*, with every CVE linked. Ransomware leak-site posts read as *Qilin claims Unident Group*.

Structured data gets short generated paragraphs: additions to CISA KEV, Windows update statistics from the Microsoft tracker, and the biggest movers on the stock watchlist.

Every digest ends with a **Coverage & limitations** section built from the run itself: how many sources were checked and which failed and why, how many raw items became how many clustered stories, and how many were dated outside the window. Stories that fit no section but score above the window's median appear under **Other notable**; the rest are counted. Sections with nothing to show are listed there as "no qualifying items from checked sources" rather than implying that nothing happened. Long digests are split across messages at section boundaries, never in the middle of an item. A run summary goes to the log channel.

### How items are understood

| Step | What it does |
|---|---|
| **Knowledge base** | MITRE ATT&CK groups and software, MISP galaxy threat actors, the CISA KEV vendor and product list and MITRE's CWE names, refreshed weekly and cached on disk, plus hand-maintained lists of ransomware groups, regulators and laws, and countries. Aliases resolve to one entity: NOBELIUM and Dark Halo are APT29 |
| **Extraction** | Threat actors, malware, vendors, products, regulators, countries, CVE ids, money amounts, victim, record and device counts, and action verbs such as arrested, indicted, exploited, breached, patched, fined and acquired |
| **Labels** | exploited, vulnerability, ransomware, breach, apt, malware, supply-chain, policy-law, law-enforcement, finance. An item can carry several |
| **Score** | Outlets covering the story, KEV status, CVSS, watchlist vendors, named actors or malware, extracted figures and first-hand sources all add to it; it decays with age |

Matching is word-based and case-aware. Names that are also ordinary words, such as Play, Royal or Progress, only match in the right case and context, so "Play ransomware gang" is the group and "Google Play Store" is not.

Labels can also route new posts to dedicated channels such as an APT tracker or a supply-chain channel. Routing is off by default. A routed item is moved, not copied: it is posted once, in the route's channel, and later coverage is merged into that post. If a route's channel is missing or lacks permissions, the item goes to its normal channel.

DOJ and Europol press releases are followed as law-enforcement sources, filtered to cyber-related items.

## Cyber-financials

The finance channel follows 17 publicly traded cybersecurity companies (CrowdStrike, Palo Alto Networks, Fortinet, Zscaler, SentinelOne, Okta, Cloudflare, Check Point, Qualys, Tenable, Rapid7, Varonis, Rubrik, SailPoint, Gen Digital, Akamai and F5) with three cybersecurity ETFs as benchmarks.

### What gets posted

| Post | When | Source |
|---|---|---|
| **SEC filings** | Within about 10 minutes of acceptance on weekdays, hourly otherwise | SEC EDGAR |
| **Press releases** | As feeds publish them | Investor relations, GlobeNewswire, Business Wire |
| **Big-move alert** | During the session, when a stock moves 7% or more from the previous close. At most one per ticker per day, plus one more past 14% | Finnhub |
| **Close summary** | Every US trading day, 20 minutes after the close. Holidays and early-close days are handled | Finnhub |
| **Earnings this week** | Mondays | Finnhub |
| **Reporting today** | On the morning of each report | Finnhub |

Filings are decoded into plain labels. For 8-Ks the item numbers are translated: 2.02 earnings results, 1.01 material agreement, 2.01 acquisition or disposition completed, 1.02 agreement terminated, 2.05 restructuring, 3.01 listing notice, 5.02 executive or director change, 5.07 shareholder vote results, 7.01 and 8.01 other announcement. 8-Ks that only carry exhibits are skipped.

Forms tracked: 8-K, 10-Q, 10-K, S-1, merger proxies, tender offers, activist stakes (Schedule 13D), and the foreign-issuer equivalents 6-K and 20-F. Insider trades and passive stakes can be switched on but are off because they are frequent and rarely newsworthy.

### One event, one post

A single earnings release usually produces an 8-K, a press release and several articles. Finance items are clustered by ticker and event type (earnings, M&A, leadership, guidance, buybacks and so on) within a 48-hour window, falling back to headline similarity for general announcements. The first item is posted; later ones become a **Filing** link or an *Also covered by* line on it. An acquisition between two watched companies is posted once, with both tickers.

### Data sources

| Source | Used for | Limits |
|---|---|---|
| [SEC EDGAR](https://www.sec.gov/search-filings/edgar-application-programming-interfaces) | Filings | 10 requests per second, contact `User-Agent` required |
| [Finnhub](https://finnhub.io) | Quotes, earnings calendar, market holidays, move-alert context | 60 calls per minute on the free tier |
| Investor relations and newswire RSS | Press releases | None |

Daily usage: about 1,770 EDGAR requests on weekdays and 410 on weekends, and about 600 Finnhub calls on trading days. Most company investor relations sites block automated clients, so press release coverage relies on the companies that publish feeds, GlobeNewswire keyword feeds and the Business Wire M&A feed. SEC filings are the authoritative record and carry the press release as an exhibit. Class-action law firm notices are filtered out.

## How deduplication works

1. **Same link, different feed.** URLs are canonicalized before hashing: tracking parameters, `www.`, `/amp` and trailing slashes are stripped, so a syndicated article is recognized everywhere.
2. **Edited slugs.** Feed GUIDs are tracked alongside URLs, so an article whose URL changes after publication is not posted twice.
3. **Same event, different outlets.** Headlines are compared with a weighted similarity in which distinctive words such as product names count more than generic ones such as "zero-day" or "patch". Articles naming the same CVE need a lower score to match. Stories stay open for merging for 72 hours.
4. **Same vulnerability, different databases.** Every CVE and GHSA id maps to one record. New information edits the existing card. Edits are batched every 45 seconds so bursts of updates don't hammer the Discord API.
5. **Restarts never repost.** All state lives in SQLite. The first poll of a new source only records its backlog, optionally posting the last few hours.

## Rate limiting

Requests to the same host are serialized and spaced out; NVD is held to its public limit of 5 requests per 30 seconds, SEC EDGAR to 4 per second and Finnhub to under 60 per minute. Feeds are fetched with ETag and Last-Modified validators, so an unchanged feed costs a bodyless `304`. `Retry-After` is honored, and a failing source backs off exponentially up to 6 hours without affecting the others. Posts to Discord are paced as well.

## Slash commands

| Command | Description |
|---|---|
| `/status` | Health of every source (last success, item count, last error) and of every configured channel |
| `/cve <id>` | The merged card for any tracked CVE or GHSA id |
| `/study <type> [window] [ticker]` | Abnormal returns after a type of event: mean, median, hit rate, t-statistic and a bootstrap confidence interval |
| `/events <ticker> [days]` | Timeline of recorded events for a ticker |
| `/kb <number>` | The stored card and CVE list for a tracked Windows security update |
| `/poll <source>` | Poll a source immediately (moderators only) |
| `/channel set <category> <channel>` | Send a category of posts (news, kev, microsoft, digest...) to a different channel, effective immediately (moderators only) |
| `/channel reset <category>` | Put a category back on the channel from the config file (moderators only) |
| `/channel list` · `/channel check` | Every category with its channel and whether the bot can post there; `check` re-tests them (moderators only) |
| `/setup layout` | Plan the category and channel layout, then apply it with a button (administrators only) |
| `/setup rollback <run_id>` | Undo a layout run from its snapshot (administrators only) |
| `/setup routes` | How many recent items each route would move, without changing anything (administrators only) |
| `/digest now [hours] [post] [private]` | Build a digest for the last N hours and reply with it in the current channel, or post it to the digest channel (moderators only) |
| `/digest status` | Next scheduled edition, enabled editions and the last run (moderators only) |
| `/entity <name> [private]` | What the knowledge base knows about an actor, malware family or vendor, and recent items mentioning it |
| `/stock <ticker>` | Latest quote and the last 5 finance items for a watchlist ticker |
| `/earnings` | Upcoming watchlist earnings over the next 14 days |

## Built with

Python 3 with `asyncio`, [discord.py](https://github.com/Rapptz/discord.py), `aiohttp`, `aiosqlite` (SQLite in WAL mode), `feedparser`, `beautifulsoup4`, `PyYAML`, `python-dotenv` and `certifi`.

## Project layout

```
cyberrssbot/
├── cyberrssbot/
│   ├── __main__.py      command line entry point
│   ├── app.py           wiring, scheduler, flush loop, health check
│   ├── classify.py      topic labels, signal score, label routing
│   ├── config.py        config loading and defaults
│   ├── digest.py        digest builder, scheduler and message splitting
│   ├── discord_bot.py   client, poster, slash commands
│   ├── engine.py        VulnEngine (merge, post, edit) and StoryEngine (clustering)
│   ├── extract.py       entity, money, count and action-verb extraction
│   ├── finance.py       watchlist, filing decoding, event classification, FinanceEngine
│   ├── kb.py            knowledge base: ATT&CK, MISP, KEV and manual gazetteers
│   ├── market.py        NYSE trading calendar
│   ├── msrc.py          MSRC CVRF parsing, KB index, revision diff, TSV export
│   ├── dedup.py         URL canonicalization, title fingerprints, story index
│   ├── http.py          per-host pacing, conditional GET, retries
│   ├── render.py        Discord embeds
│   ├── store.py         SQLite schema and queries
│   ├── upgrade.py       adds new settings and sources to an existing config file
│   ├── util.py          shared helpers
│   └── sources/
│       ├── base.py      source base class
│       ├── feeds.py     RSS / Atom and scrape sources
│       ├── finance.py   SEC EDGAR, quotes, earnings and company news sources
│       ├── msrc.py      Windows security update tracker
│       └── vulns.py     NVD, KEV, GHSA and EPSS sources
├── kb/                  manual lists: actors, ransomware groups, regulators, countries
├── install.sh           installer and updater for a Debian or Ubuntu host
├── config.example.yaml
├── .env.example
└── requirements.txt
```

## License

Copyright © 2026 miikie. All rights reserved.

This code is published for viewing only. You may not use, copy, modify, merge, publish, distribute, sublicense or sell it, in whole or in part, without prior written permission. See [LICENSE](LICENSE).

Market data is provided for information only, may be delayed and is not financial advice.
