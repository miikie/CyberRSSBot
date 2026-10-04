from __future__ import annotations

import copy
import os
import re
import shutil
import sys
import time

import yaml

SOURCE_KEYS = ("primary", "labels", "quote")
CHANNEL_MOVES = {"sec-edgar": ("finance", "finance-filings"), "fin-quotes": ("finance", "finance-tape"),
                 "fin-earnings": ("finance", "finance-earnings")}
KEEP_AS_IS = {("finance", "companies"), ("finance", "benchmarks")}
_ID_RE = re.compile(r"\d{15,21}")


class _Dumper(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


def _add_missing(target: dict, example: dict, path: tuple[str, ...], changes: list[str]) -> None:
    for key, value in example.items():
        here = (*path, str(key))
        if here in KEEP_AS_IS or here == ("sources",):
            continue
        if key not in target:
            target[key] = copy.deepcopy(value)
            changes.append("added " + ".".join(here))
        elif isinstance(value, dict) and isinstance(target[key], dict):
            _add_missing(target[key], value, here, changes)


def merge_config(config: dict, example: dict) -> list[str]:
    changes: list[str] = []
    _add_missing(config, example, (), changes)

    sources = config.setdefault("sources", [])
    by_id = {s.get("id"): s for s in sources}
    previous = None
    for wanted in example.get("sources") or []:
        sid = wanted.get("id")
        mine = by_id.get(sid)
        if mine is None:
            position = sources.index(by_id[previous]) + 1 if previous in by_id else len(sources)
            mine = copy.deepcopy(wanted)
            sources.insert(position, mine)
            by_id[sid] = mine
            state = "" if wanted.get("enabled", True) else " (disabled)"
            changes.append(f"added source {sid}{state}")
        else:
            for key in SOURCE_KEYS:
                if key in wanted and key not in mine:
                    mine[key] = copy.deepcopy(wanted[key])
                    changes.append(f"set {key} on source {sid}")
            old, new = CHANNEL_MOVES.get(sid, (None, None))
            if old and mine.get("channel") == old and wanted.get("channel") == new:
                mine["channel"] = new
                changes.append(f"moved source {sid} from channel {old} to {new}")
        previous = sid
    return changes


def unset_channels(config: dict) -> list[str]:
    channels = (config.get("discord") or {}).get("channels") or {}
    return [key for key, value in channels.items() if not value]


def _ask(prompt: str) -> str:
    try:
        return input(prompt).strip()
    except EOFError:
        return ""


def prompt_settings(config: dict) -> list[str]:
    changes = []
    channels = config.setdefault("discord", {}).setdefault("channels", {})
    routes = set(config.get("routing") or {})
    for key in unset_channels(config):
        note = " (only needed if you enable that route)" if key in routes else ""
        while True:
            answer = _ask(f"Channel ID for '{key}'{note}, Enter to skip: ")
            if not answer:
                break
            if _ID_RE.fullmatch(answer):
                channels[key] = int(answer)
                changes.append(f"set discord.channels.{key}")
                break
            print("  That doesn't look like a channel ID (15 to 21 digits).")
    digest = config.get("digest") or {}
    if digest and not digest.get("enabled") and channels.get(digest.get("channel") or "digest"):
        if _ask("Post scheduled digests to the digest channel? [y/N]: ").lower() in ("y", "yes"):
            digest["enabled"] = True
            changes.append("set digest.enabled to true")
    return changes


def upgrade_config(config_path: str, example_path: str, *, interactive: bool | None = None) -> list[str]:
    with open(config_path, encoding="utf-8") as fh:
        config = yaml.safe_load(fh) or {}
    with open(example_path, encoding="utf-8") as fh:
        example = yaml.safe_load(fh) or {}
    changes = merge_config(config, example)
    if interactive if interactive is not None else sys.stdin.isatty():
        changes += prompt_settings(config)
    if not changes:
        return []
    backup = f"{config_path}.{time.strftime('%Y%m%d-%H%M%S')}.bak"
    shutil.copy2(config_path, backup)
    tmp = config_path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        yaml.dump(config, fh, Dumper=_Dumper, sort_keys=False, allow_unicode=True, width=110,
                  default_flow_style=False)
    shutil.copymode(config_path, tmp)
    os.replace(tmp, config_path)
    return changes + [f"previous version kept as {os.path.basename(backup)}"]


def run(config_path: str, example_path: str) -> int:
    if not os.path.isfile(config_path):
        print(f"{config_path} doesn't exist; nothing to upgrade.")
        return 1
    if not os.path.isfile(example_path):
        print(f"{example_path} doesn't exist; can't tell which settings are new.")
        return 1
    changes = upgrade_config(config_path, example_path)
    if not changes:
        print(f"{config_path} already has every setting and source from {example_path}.")
        return 0
    print(f"Updated {config_path}:")
    for change in changes:
        print(f"  - {change}")
    left = unset_channels(yaml.safe_load(open(config_path, encoding="utf-8")) or {})
    if left:
        print("Channels still set to 0 (their posts go to the default channel, or nowhere for digests): "
              + ", ".join(left))
    return 0
