from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field

import discord

log = logging.getLogger(__name__)

BOT_ALLOW = ("view_channel", "send_messages", "embed_links", "attach_files", "read_message_history")
PERM_LABELS = {"view_channel": "View Channel", "send_messages": "Send Messages", "embed_links": "Embed Links",
               "attach_files": "Attach Files", "read_message_history": "Read Message History"}
SNAPSHOT_PREFIX = "layout.snapshot."
CATEGORY_PREFIX = "layout.category."
APPLIED_FILE = "layout-applied.yaml"


@dataclass
class LayoutChannel:
    name: str
    keys: list[str]
    category: str
    private: bool
    split: bool = False
    channel_id: int | None = None
    via: str | None = None
    current_name: str | None = None
    current_category: int | None = None
    contested_by: str | None = None


@dataclass
class LayoutCategory:
    name: str
    private: bool
    channels: list[LayoutChannel]
    category_id: int | None = None


@dataclass
class Plan:
    categories: list[LayoutCategory]
    archive_name: str
    archive_id: int | None
    rename_existing: bool
    feeds_read_only: bool
    retired: list[dict] = field(default_factory=list)
    unmanaged: list[str] = field(default_factory=list)
    ops: list[tuple[str, str]] = field(default_factory=list)
    mapping: dict[str, str] = field(default_factory=dict)
    mapping_changes: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def changes(self) -> int:
        return len(self.ops) + len(self.mapping_changes)

    def channels(self) -> list[LayoutChannel]:
        return [ch for cat in self.categories for ch in cat.channels]


def parse_layout(cfg: dict) -> dict:
    raw = cfg.get("layout") or {}
    categories = []
    for cat in raw.get("categories") or []:
        channels = [{"name": str(c["name"]), "keys": [str(k) for k in c.get("keys") or []],
                     "split": bool(c.get("split"))} for c in cat.get("channels") or []]
        categories.append({"name": str(cat["name"]), "private": bool(cat.get("private")), "channels": channels})
    return {"rename_existing": bool(raw.get("rename_existing", True)),
            "feeds_read_only": bool(raw.get("feeds_read_only", True)),
            "archive_category": str(raw.get("archive_category") or "Archive"), "categories": categories}


def layout_keys(layout: dict) -> list[str]:
    return [k for cat in layout["categories"] for ch in cat["channels"] for k in ch["keys"]]


def _text_channel(guild, channel_id: int):
    if not channel_id:
        return None
    channel = guild.get_channel(int(channel_id))
    if channel is None or isinstance(channel, discord.CategoryChannel) or getattr(channel, "is_category", False):
        return None
    return channel


def _category(channel) -> int | None:
    return getattr(channel, "category_id", None)


def find_category(guild, name: str, stored: dict[str, int]):
    if stored.get(name):
        found = guild.get_channel(int(stored[name]))
        if found is not None:
            return found
    return next((c for c in guild.categories if c.name == name), None)


def desired_overwrites(*, private: bool, read_only: bool, archived: bool = False) -> dict[str, dict[str, bool]]:
    everyone: dict[str, bool] = {}
    if private:
        everyone["view_channel"] = False
    elif read_only or archived:
        everyone["send_messages"] = False
    return {"everyone": everyone, "bot": {attr: True for attr in BOT_ALLOW}}


def overwrite_changes(obj, target, wanted: dict[str, bool]) -> dict[str, bool]:
    current = obj.overwrites_for(target) if obj is not None else discord.PermissionOverwrite()
    return {attr: value for attr, value in wanted.items() if getattr(current, attr) is not value}


def _describe(changes: dict[str, bool]) -> str:
    allow = [PERM_LABELS.get(a, a) for a, v in changes.items() if v]
    deny = [PERM_LABELS.get(a, a) for a, v in changes.items() if not v]
    parts = []
    if allow:
        parts.append("allow " + ", ".join(allow))
    if deny:
        parts.append("deny " + ", ".join(deny))
    return "; ".join(parts)


def _ordered(objects: list) -> list:
    return sorted(objects, key=lambda o: (o.position, o.id))


def build_plan(cfg: dict, guild, resolved: dict[str, int], stored_categories: dict[str, int]) -> Plan:
    layout = parse_layout(cfg)
    everyone, me = guild.default_role, guild.me
    plan = Plan([], layout["archive_category"], None, layout["rename_existing"], layout["feeds_read_only"])

    for cat in layout["categories"]:
        found = find_category(guild, cat["name"], stored_categories)
        plan.categories.append(LayoutCategory(cat["name"], cat["private"], [
            LayoutChannel(c["name"], c["keys"], cat["name"], cat["private"], c["split"]) for c in cat["channels"]
        ], found.id if found else None))
    archive = find_category(guild, plan.archive_name, stored_categories)
    plan.archive_id = archive.id if archive else None

    claims: dict[int, list[LayoutChannel]] = {}
    for ch in plan.channels():
        for key in ch.keys:
            existing = _text_channel(guild, resolved.get(key, 0))
            if existing is not None:
                claims.setdefault(existing.id, [])
                if ch not in claims[existing.id]:
                    claims[existing.id].append(ch)

    adopted: dict[int, LayoutChannel] = {}
    for ch in plan.channels():
        for key in ch.keys:
            existing = _text_channel(guild, resolved.get(key, 0))
            if existing is None:
                continue
            others = [o for o in claims[existing.id] if o is not ch]
            if ch.split and others:
                continue
            if existing.id in adopted:
                ch.contested_by = adopted[existing.id].name
                continue
            adopted[existing.id] = ch
            ch.channel_id, ch.via = existing.id, key
            ch.current_name, ch.current_category = existing.name, _category(existing)
            break
        if ch.contested_by and ch.channel_id is None:
            plan.warnings.append(f"#{ch.name} shares a channel with #{ch.contested_by}; the first in layout order "
                                 f"keeps it and #{ch.name} is created. Mark one of them `split: true` to choose.")

    for ch in plan.channels():
        for key in ch.keys:
            plan.mapping[key] = ch.name

    referenced = {}
    for key, cid in resolved.items():
        channel = _text_channel(guild, cid)
        if channel is not None:
            referenced.setdefault(channel.id, []).append(key)
    for cid, keys in sorted(referenced.items(), key=lambda kv: (_text_channel(guild, kv[0]).position, kv[0])):
        if cid in adopted:
            continue
        channel = _text_channel(guild, cid)
        unplaced = [k for k in keys if k not in plan.mapping]
        if unplaced:
            plan.warnings.append(f"#{channel.name} is used by {', '.join(unplaced)}, which the layout doesn't "
                                 "place; it is left where it is.")
            continue
        homes = sorted({plan.mapping[k] for k in keys})
        plan.retired.append({"id": cid, "name": channel.name, "keys": keys, "now": homes,
                             "category": _category(channel)})

    managed = set(adopted) | {r["id"] for r in plan.retired}
    managed_categories = {c.category_id for c in plan.categories if c.category_id} | (
        {plan.archive_id} if plan.archive_id else set())
    for channel in _ordered([c for c in guild.channels if not isinstance(c, discord.CategoryChannel)
                             and not getattr(c, "is_category", False)]):
        if channel.id not in managed:
            kind = getattr(getattr(channel, "type", None), "name", "text")
            plan.unmanaged.append(f"#{channel.name}" + ("" if kind in ("text", "news") else f" ({kind})"))
            home = next((c.name for c in plan.categories if c.category_id and c.category_id == _category(channel)),
                        None)
            if home:
                cat = home
                plan.warnings.append(f"#{channel.name} sits in {cat}, which the layout manages. The channel itself "
                                     "is not changed, but it is not reordered either.")
    for category in _ordered(list(guild.categories)):
        if category.id not in managed_categories:
            plan.unmanaged.append(f"category {category.name}")

    ops = plan.ops
    for cat in plan.categories:
        if cat.category_id is None:
            ops.append(("create_category", cat.name))
    if plan.retired and plan.archive_id is None:
        ops.append(("create_category", plan.archive_name))

    for cat in plan.categories:
        for ch in cat.channels:
            if ch.channel_id is None:
                ops.append(("create_channel", f"#{ch.name} in {cat.name}"))
                continue
            if plan.rename_existing and ch.current_name != ch.name:
                ops.append(("rename", f"#{ch.current_name} → #{ch.name}"))
            if cat.category_id is None or ch.current_category != cat.category_id:
                ops.append(("move", f"#{ch.name} into {cat.name}"))
    for r in plan.retired:
        if plan.archive_id is None or r["category"] != plan.archive_id:
            ops.append(("retire", f"#{r['name']} to {plan.archive_name}"))

    def perm_ops(label: str, obj, wanted: dict[str, dict[str, bool]]) -> None:
        for who, target in (("@everyone", everyone), ("bot", me)):
            changes = overwrite_changes(obj, target, wanted["everyone" if who == "@everyone" else "bot"])
            if changes:
                ops.append(("permission", f"{label}: {who} {_describe(changes)}"))

    for cat in plan.categories:
        obj = guild.get_channel(cat.category_id) if cat.category_id else None
        if cat.private:
            perm_ops(cat.name, obj, desired_overwrites(private=True, read_only=False))
        for ch in cat.channels:
            obj = guild.get_channel(ch.channel_id) if ch.channel_id else None
            perm_ops(f"#{ch.name}", obj, desired_overwrites(private=cat.private, read_only=plan.feeds_read_only))
    if plan.retired or plan.archive_id:
        obj = guild.get_channel(plan.archive_id) if plan.archive_id else None
        perm_ops(plan.archive_name, obj, desired_overwrites(private=False, read_only=False, archived=True))
    for r in plan.retired:
        perm_ops(f"#{r['name']} (archived)", guild.get_channel(r["id"]),
                 desired_overwrites(private=False, read_only=False, archived=True))

    wanted_categories = [c.category_id for c in plan.categories] + ([plan.archive_id] if plan.retired or
                                                                    plan.archive_id else [])
    if None in wanted_categories or not _in_order(guild, wanted_categories):
        ops.append(("order", "categories in layout order, Archive last"))
    for cat in plan.categories:
        ids = [ch.channel_id for ch in cat.channels]
        moved = any(ch.channel_id is not None and ch.current_category != cat.category_id for ch in cat.channels)
        if len(ids) > 1 and (None in ids or cat.category_id is None or moved or not _in_order(guild, ids)):
            ops.append(("order", f"channels in {cat.name} as listed"))

    for ch in plan.channels():
        for key in ch.keys:
            if ch.channel_id is None or resolved.get(key, 0) != ch.channel_id:
                plan.mapping_changes.append(key)
    return plan


def _in_order(guild, ids: list) -> bool:
    objs = [guild.get_channel(i) for i in ids]
    if any(o is None for o in objs):
        return False
    return [o.id for o in _ordered(objs)] == [o.id for o in objs]


def render_plan(plan: Plan, resolved: dict[str, int], guild) -> str:
    def name_of(cid):
        channel = guild.get_channel(cid) if cid else None
        return f"#{channel.name}" if channel else f"ID {cid}"

    lines = [f"Layout plan: {plan.changes} change{'s' if plan.changes != 1 else ''}"]
    if not plan.changes:
        lines.append("The server already matches the layout. Nothing to do.")
    created = [c.name for c in plan.categories if c.category_id is None]
    if plan.retired and plan.archive_id is None:
        created.append(plan.archive_name)
    lines += ["", "Categories to create:"] + ([f"  + {n}" for n in created] or ["  none"])

    lines += ["", "Channels (in final order):"]
    for cat in plan.categories:
        lines.append(f"  {cat.name}" + (" (private)" if cat.private else ""))
        for ch in cat.channels:
            if ch.channel_id is None:
                why = f", split off #{ch.contested_by}" if ch.contested_by else ""
                shared = [k for k in ch.keys if resolved.get(k)]
                if ch.split and shared:
                    why = f", split from {name_of(resolved[shared[0]])}"
                lines.append(f"    #{ch.name}: create{why} (keys: {', '.join(ch.keys)})")
                continue
            parts = [f"adopt {name_of(ch.channel_id)} (ID {ch.channel_id}) via `{ch.via}`"]
            if plan.rename_existing and ch.current_name != ch.name:
                parts.append(f"rename to #{ch.name}")
            if cat.category_id is None or ch.current_category != cat.category_id:
                parts.append(f"move into {cat.name}")
            lines.append(f"    #{ch.name}: {', '.join(parts)} (keys: {', '.join(ch.keys)})")

    lines += ["", f"Retire to {plan.archive_name} (read-only, history kept):"]
    lines += [f"  #{r['name']} (ID {r['id']}): keys {', '.join(r['keys'])} now post to "
              f"{', '.join('#' + n for n in r['now'])}" for r in plan.retired] or ["  none"]

    perms = [d for kind, d in plan.ops if kind == "permission"]
    lines += ["", "Permission changes:"] + ([f"  {p}" for p in perms] or ["  none"])
    orders = [d for kind, d in plan.ops if kind == "order"]
    lines += ["", "Ordering:"] + ([f"  {o}" for o in orders] or ["  already in order"])

    lines += ["", "Key → channel after apply:"]
    for ch in plan.channels():
        changed = [k for k in ch.keys if k in plan.mapping_changes]
        note = f" (changes: {', '.join(changed)})" if changed else ""
        lines.append(f"  {', '.join(ch.keys)} → #{ch.name}{note}")

    lines += ["", "Left alone (not referenced by any key):"] + ([f"  {u}" for u in plan.unmanaged] or ["  none"])
    if plan.warnings:
        lines += ["", "Warnings:"] + [f"  ! {w}" for w in plan.warnings]
    return "\n".join(lines)


def bot_name(guild) -> str:
    me = getattr(guild, "me", None)
    return getattr(me, "display_name", None) or getattr(me, "name", None) or "Bot"


def _target_kind(target) -> str:
    if isinstance(target, discord.Role) or getattr(target, "is_role", False):
        return "role"
    return "member"


def _snapshot_obj(obj) -> dict:
    overwrites = []
    for target, ow in obj.overwrites.items():
        allow, deny = ow.pair()
        overwrites.append({"id": target.id, "type": _target_kind(target), "allow": allow.value, "deny": deny.value})
    return {"name": obj.name, "category": _category(obj), "position": obj.position,
            "overwrites": sorted(overwrites, key=lambda o: (o["type"], o["id"]))}


class LayoutError(Exception):
    pass


class Applier:
    def __init__(self, app, guild, cfg: dict):
        self.app, self.guild, self.cfg = app, guild, cfg
        self.store, self.poster = app.store, app.poster
        self.run_id = "layout-" + time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        self.reason = f"{bot_name(guild)} layout {self.run_id}"
        self.snapshot: dict = {}
        self.done: list[str] = []

    async def _save(self) -> None:
        await self.store.setting_set(SNAPSHOT_PREFIX + self.run_id, json.dumps(self.snapshot, sort_keys=True))

    def _remember(self, obj) -> None:
        bucket = "categories" if isinstance(obj, discord.CategoryChannel) or getattr(obj, "is_category", False) \
            else "channels"
        self.snapshot[bucket].setdefault(str(obj.id), _snapshot_obj(obj))

    async def _set_overwrites(self, obj, wanted: dict[str, dict[str, bool]], label: str) -> None:
        for who, target in (("everyone", self.guild.default_role), ("bot", self.guild.me)):
            changes = overwrite_changes(obj, target, wanted[who])
            if not changes:
                continue
            overwrite = obj.overwrites_for(target)
            overwrite.update(**changes)
            await obj.set_permissions(target, overwrite=overwrite, reason=self.reason)
            self.done.append(f"permissions on {label}: {'@everyone' if who == 'everyone' else 'bot'} "
                             f"{_describe(changes)}")

    async def apply(self) -> dict:
        guild = self.guild
        stored = await self.store.settings_get(CATEGORY_PREFIX)
        resolved = dict(self.poster.channels)
        plan = build_plan(self.cfg, guild, resolved, {k: int(v) for k, v in stored.items()})
        self.snapshot = {"run_id": self.run_id, "created_at": int(time.time()), "status": "applying",
                         "channels": {}, "categories": {}, "created_channels": [], "created_categories": [],
                         "overrides_before": await self.store.settings_get("channel:"), "applied": [], "error": None}
        for ch in plan.channels():
            if ch.channel_id:
                self._remember(guild.get_channel(ch.channel_id))
        for r in plan.retired:
            self._remember(guild.get_channel(r["id"]))
        for cat in plan.categories:
            if cat.category_id:
                self._remember(guild.get_channel(cat.category_id))
        if plan.archive_id:
            self._remember(guild.get_channel(plan.archive_id))
        await self._save()
        try:
            await self._run(plan)
        except Exception as exc:
            log.exception("layout %s failed", self.run_id)
            self.snapshot.update(status="failed", error=f"{type(exc).__name__}: {exc}", applied=self.done)
            await self._save()
            return {"run_id": self.run_id, "ok": False, "applied": self.done, "error": self.snapshot["error"]}
        self.snapshot.update(status="applied", applied=self.done)
        await self._save()
        return {"run_id": self.run_id, "ok": True, "applied": self.done, "error": None,
                "mapping": self.mapping, "problems": self.problems}

    async def _category(self, name: str, existing_id: int | None):
        if existing_id:
            return self.guild.get_channel(existing_id)
        category = await self.guild.create_category(name, reason=self.reason)
        self.snapshot["created_categories"].append(category.id)
        await self.store.setting_set(CATEGORY_PREFIX + name, str(category.id))
        await self._save()
        self.done.append(f"created category {name}")
        return category

    async def _run(self, plan: Plan) -> None:
        guild = self.guild
        categories = {}
        for cat in plan.categories:
            categories[cat.name] = await self._category(cat.name, cat.category_id)
        archive = None
        if plan.retired or plan.archive_id:
            archive = await self._category(plan.archive_name, plan.archive_id)

        channels: dict[str, object] = {}
        for cat in plan.categories:
            target = categories[cat.name]
            for ch in cat.channels:
                if ch.channel_id is None:
                    created = await guild.create_text_channel(ch.name, category=target, reason=self.reason)
                    self.snapshot["created_channels"].append(created.id)
                    await self._save()
                    self.done.append(f"created #{ch.name} in {cat.name}")
                    channels[ch.name] = created
                    continue
                channel = guild.get_channel(ch.channel_id)
                edits = {}
                if plan.rename_existing and channel.name != ch.name:
                    edits["name"] = ch.name
                if _category(channel) != target.id:
                    edits["category"] = target
                if edits:
                    old = channel.name
                    await channel.edit(**edits, sync_permissions=False, reason=self.reason)
                    what = []
                    if "name" in edits:
                        what.append(f"renamed to #{ch.name}")
                    if "category" in edits:
                        what.append(f"moved into {cat.name}")
                    self.done.append(f"#{old}: {', '.join(what)}")
                channels[ch.name] = channel

        for r in plan.retired:
            channel = guild.get_channel(r["id"])
            if _category(channel) != archive.id:
                await channel.edit(category=archive, sync_permissions=False, reason=self.reason)
                self.done.append(f"retired #{channel.name} to {plan.archive_name}")

        for cat in plan.categories:
            if cat.private:
                await self._set_overwrites(categories[cat.name], desired_overwrites(private=True, read_only=False),
                                           cat.name)
            for ch in cat.channels:
                await self._set_overwrites(channels[ch.name], desired_overwrites(
                    private=cat.private, read_only=plan.feeds_read_only), f"#{ch.name}")
        if archive is not None:
            archived = desired_overwrites(private=False, read_only=False, archived=True)
            await self._set_overwrites(archive, archived, plan.archive_name)
            for r in plan.retired:
                await self._set_overwrites(guild.get_channel(r["id"]), archived, f"#{r['name']}")

        ordered_categories = [categories[c.name] for c in plan.categories] + ([archive] if archive else [])
        await self._order(ordered_categories, "categories")
        for cat in plan.categories:
            await self._order([channels[ch.name] for ch in cat.channels], f"channels in {cat.name}")

        self.mapping = {key: channels[ch.name].id for ch in plan.channels() for key in ch.keys}
        changed = {k: v for k, v in self.mapping.items() if self.poster.channels.get(k) != v}
        self.problems = await self.poster.set_channels(self.store, changed)
        if changed:
            self.done.append(f"pointed {len(changed)} channel key{'s' if len(changed) != 1 else ''} at the layout")
        write_applied(self.run_id, self.poster.channels)

    async def _order(self, objs: list, label: str) -> None:
        if len(objs) < 2 or [o.id for o in _ordered(objs)] == [o.id for o in objs]:
            return
        base = min(o.position for o in objs)
        for index, obj in enumerate(objs):
            if obj.position != base + index:
                await obj.edit(position=base + index, reason=self.reason)
        self.done.append(f"ordered {label}")


def write_applied(run_id: str, channels: dict[str, int], path: str = APPLIED_FILE) -> None:
    lines = [f"# Written by /setup layout ({run_id}).",
             "# Paste this block into config.yaml under `discord:`, restart, then run /channel reset for each key",
             "# (or leave the overrides in place: they take precedence over config.yaml either way).",
             "discord:", "  channels:"]
    lines += [f"    {key}: {value}" for key, value in channels.items()]
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")


async def rollback(app, guild, run_id: str) -> dict:
    store, poster = app.store, app.poster
    raw = await store.setting_get(SNAPSHOT_PREFIX + run_id)
    if raw is None:
        raise LayoutError(f"no layout snapshot called `{run_id}`")
    snap = json.loads(raw)
    reason = f"{bot_name(guild)} layout rollback {run_id}"
    done = []
    archive_name = parse_layout(app.cfg)["archive_category"]
    stored = {k: int(v) for k, v in (await store.settings_get(CATEGORY_PREFIX)).items()}
    archive = find_category(guild, archive_name, stored)

    for cid in snap["created_channels"]:
        channel = guild.get_channel(cid)
        if channel is not None and archive is not None and _category(channel) != archive.id:
            await channel.edit(category=archive, sync_permissions=False, reason=reason)
            done.append(f"moved created #{channel.name} to {archive_name}")

    for bucket in ("categories", "channels"):
        for cid, before in snap[bucket].items():
            obj = guild.get_channel(int(cid))
            if obj is None:
                done.append(f"ID {cid} no longer exists; skipped")
                continue
            edits = {}
            if obj.name != before["name"]:
                edits["name"] = before["name"]
            if bucket == "channels" and _category(obj) != before["category"]:
                edits["category"] = guild.get_channel(before["category"]) if before["category"] else None
            if obj.position != before["position"]:
                edits["position"] = before["position"]
            if edits:
                if bucket == "channels":
                    edits["sync_permissions"] = False
                await obj.edit(**edits, reason=reason)
                done.append(f"restored {before['name']}")
            wanted = {o["id"]: o for o in before["overwrites"]}
            for target in list(obj.overwrites):
                if target.id not in wanted:
                    await obj.set_permissions(target, overwrite=None, reason=reason)
            for o in before["overwrites"]:
                target = guild.get_role(o["id"]) if o["type"] == "role" else guild.get_member(o["id"])
                if target is None:
                    continue
                overwrite = discord.PermissionOverwrite.from_pair(discord.Permissions(o["allow"]),
                                                                  discord.Permissions(o["deny"]))
                if obj.overwrites_for(target) != overwrite:
                    await obj.set_permissions(target, overwrite=overwrite, reason=reason)

    before = snap["overrides_before"]
    current = await store.settings_get("channel:")
    for key in current:
        if key not in before:
            await store.setting_delete("channel:" + key)
    for key, value in before.items():
        await store.setting_set("channel:" + key, value)
    await poster.load_overrides(store)
    await poster.validate_channels()
    done.append("restored channel overrides")
    snap["status"] = "rolled_back"
    await store.setting_set(SNAPSHOT_PREFIX + run_id, json.dumps(snap, sort_keys=True))
    return {"run_id": run_id, "done": done}


async def route_preview(app, days: int = 7, examples: int = 3) -> list[dict]:
    intel, poster, store = app.intel, app.poster, app.store
    now = time.time()
    since = now - days * 86400
    items = []
    for row in await store.stories_between(since, now + 1):
        d = row["data"]
        _, labels = intel.analyze(d["title"], d.get("summary") or "", source=d["source"])
        items.append((row["ts"], d.get("channel") or "news", d["title"], labels))
    for row in await store.vulns_window(since, now + 1):
        d = row["data"]
        if row["posted"] != 1 or d.get("kev") or row["first_seen"] < since:
            continue
        _, labels = intel.analyze(d.get("title") or "", d.get("description") or "", kind="vuln", vuln=d)
        items.append((row["first_seen"], "vulns", f"{d['id']} {d.get('title') or ''}".strip(), labels))
    items.sort(key=lambda i: -i[0])

    out = []
    for name, rule in (app.cfg.get("routing") or {}).items():
        if not isinstance(rule, dict):
            continue
        wanted = set(rule.get("labels") or [])
        target = poster.channels.get(name, 0)
        moved = [i for i in items if wanted & set(i[3]) and (not target or poster.channels.get(i[1], 0) != target)]
        out.append({"route": name, "labels": sorted(wanted), "enabled": bool(rule.get("enabled", True)),
                    "target": target, "count": len(moved), "examples": [i[2] for i in moved[:examples]],
                    "from": sorted({i[1] for i in moved})})
    return out
