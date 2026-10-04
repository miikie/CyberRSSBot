from __future__ import annotations

import os

import yaml
from dotenv import load_dotenv

DEFAULTS = {
    "database": "cyberrssbot.db",
    "discord": {"guild_id": 0, "channels": {}, "post_gap_seconds": 1.5, "kev_ping_role_id": 0,
                "microsoft_ping_role_id": 0},
    "poll": {"default_interval": 1200, "max_age_days": 7, "first_run_lookback_hours": 0},
    "network": {"timeout": 45, "host_min_interval_default": 2.0, "host_min_interval": {}},
    "dedup": {
        "story_window_hours": 72,
        "title_threshold": 0.5,
        "cve_title_threshold": 0.25,
        "fold_cve_news": False,
    },
    "filters": {
        "vulns": {
            "min_cvss": 8.0,
            "min_epss": 0.10,
            "watch_min_cvss": 6.5,
            "max_age_days": 30,
            "watchlist": [],
            "mute_cnas": [],
            "mute_patterns": [],
        }
    },
    "finance": {
        "sec_contact_name": "CyberRSSBot",
        "move_alert_pct": 7.0,
        "summary_delay_minutes": 20,
        "cluster_window_hours": 48,
        "filings": {"form4": False, "schedule_13g": False},
        "earnings": {"weekly_weekday": 0, "weekly_hour_utc": 13, "same_day_reminder": True,
                     "reminder_hour_et": 8, "refresh_hours": 12, "horizon_days": 90},
        "companies": {},
        "benchmarks": {},
    },
    "kb": {"cache_dir": "kb_cache", "extras_dir": "kb", "refresh_days": 7, "use_misp": True},
    "routing": {},
    "digest": {
        "enabled": False, "channel": "digest", "top_n": 5, "max_words": 40, "min_score": 0,
        "late_grace_hours": 6, "max_message_chars": 3800, "post_empty": True, "catch_up_minutes": 90,
        "entity_lookback_days": 14, "weights": {},
        "other": {"enabled": True, "title": "Other notable", "top_n": 3},
    },
    "sources": [],
}

FINNHUB_TYPES = {"quotes", "earnings", "company_news"}


def _deep_merge(base: dict, override: dict | None) -> dict:
    out = dict(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def load_config(path: str = "config.yaml") -> dict:
    load_dotenv()
    with open(path, encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}
    cfg = _deep_merge(DEFAULTS, raw)
    cfg["secrets"] = {
        "discord_token": os.getenv("DISCORD_TOKEN", "").strip(),
        "nvd_api_key": os.getenv("NVD_API_KEY", "").strip() or None,
        "github_token": os.getenv("GITHUB_TOKEN", "").strip() or None,
        "finnhub_api_key": os.getenv("FINNHUB_API_KEY", "").strip() or None,
        "sec_user_agent": _sec_user_agent(cfg),
    }
    ids = [s.get("id") for s in cfg["sources"]]
    if None in ids:
        raise ValueError("every source in config.yaml needs an `id`")
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    if dupes:
        raise ValueError(f"duplicate source ids in config.yaml: {dupes}")
    enabled = {s.get("type", "rss") for s in cfg["sources"] if s.get("enabled", True)}
    if "sec_edgar" in enabled and not cfg["secrets"]["sec_user_agent"]:
        raise ValueError("a sec_edgar source is enabled but neither SEC_USER_AGENT nor MAIN_EMAIL is set in .env "
                         "(SEC requires a contact User-Agent such as \"YourBot you@example.com\")")
    if enabled & FINNHUB_TYPES and not cfg["secrets"]["finnhub_api_key"]:
        raise ValueError(f"{sorted(enabled & FINNHUB_TYPES)} sources need FINNHUB_API_KEY in .env "
                         "(free key at https://finnhub.io/register)")
    return cfg


def _sec_user_agent(cfg: dict) -> str | None:
    explicit = os.getenv("SEC_USER_AGENT", "").strip()
    if explicit:
        return explicit
    email = os.getenv("MAIN_EMAIL", "").strip()
    if email:
        return f"{cfg['finance'].get('sec_contact_name') or 'CyberRSSBot'} {email}"
    return None
