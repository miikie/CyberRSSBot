# CyberRSSBot

A Discord bot that aggregates cybersecurity news, advisories, threat research and vulnerability intelligence from 51 sources, tracks publicly traded cybersecurity companies, routes everything to topic channels and makes sure every event shows up **once**.

Vulnerabilities reported by NVD, GitHub, MSRC, CISA KEV and FIRST EPSS are merged into a single card per CVE that is edited in place as new information arrives. News stories covered by several outlets are posted once, with the other outlets listed under it.

> This repository is a public showcase of a private project. It is not a product and is not licensed for use, modification or redistribution. See [License](#license).

## Contents

- [Features](#features)
- [Channels](#channels)
- [Sources](#sources)
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
- **Self-monitoring.** `/status` shows the health of every source, and repeated failures and recoveries are reported to a log channel.
- **Scraper for feedless sites.** Any page can become a source with a CSS selector.
- **Cyber-financials.** SEC filings, press releases, a daily close summary, big-move alerts and an earnings calendar for a watchlist of security stocks.

## Channels

| Channel | Contents |
|---|---|
| Actively exploited | New CISA KEV entries, plus an escalation when an already-posted CVE is added to KEV |
| CVEs | One card per CVE / GHSA, merged from NVD, GitHub Advisories, MSRC, KEV and EPSS |
| Advisories | Government CERTs and vendor PSIRTs |
| Articles | Security journalism |
| Threat intel | Vendor threat intelligence and exploit research |
| DFIR | Incident write-ups and handler diaries |
| Data breaches | Breach reports and newly loaded breach corpora |
| Ransomware | Ransomware leak-site victim postings |
| Malware | Malware analysis, sandbox and traffic research |
| Finance | SEC filings, press releases, move alerts, the daily close summary and earnings posts |
| Bot log | Source failure and recovery notices |

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
| Finance | SEC EDGAR, Finnhub, Cloudflare and Gen Digital investor relations, GlobeNewswire, Business Wire |

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
| `/status` | Health of every source: last success, item count and last error |
| `/cve <id>` | The merged card for any tracked CVE or GHSA id |
| `/poll <source>` | Poll a source immediately (moderators only) |
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
│   ├── config.py        config loading and defaults
│   ├── discord_bot.py   client, poster, slash commands
│   ├── engine.py        VulnEngine (merge, post, edit) and StoryEngine (clustering)
│   ├── finance.py       watchlist, filing decoding, event classification, FinanceEngine
│   ├── market.py        NYSE trading calendar
│   ├── dedup.py         URL canonicalization, title fingerprints, story index
│   ├── http.py          per-host pacing, conditional GET, retries
│   ├── render.py        Discord embeds
│   ├── store.py         SQLite schema and queries
│   ├── util.py          shared helpers
│   └── sources/
│       ├── base.py      source base class
│       ├── feeds.py     RSS / Atom and scrape sources
│       ├── finance.py   SEC EDGAR, quotes, earnings and company news sources
│       └── vulns.py     NVD, KEV, GHSA and EPSS sources
├── config.example.yaml
├── .env.example
└── requirements.txt
```

## License

Copyright © 2026 miikie. All rights reserved.

This code is published for viewing only. You may not use, copy, modify, merge, publish, distribute, sublicense or sell it, in whole or in part, without prior written permission. See [LICENSE](LICENSE).

Market data is provided for information only, may be delayed and is not financial advice.
