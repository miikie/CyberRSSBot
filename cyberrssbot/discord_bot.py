from __future__ import annotations

import asyncio
import io
import logging
import time
from datetime import datetime, timedelta, timezone

import discord
from discord import app_commands

from . import layout, msrc, render

log = logging.getLogger("cyberrssbot.discord")

REQUIRED_PERMISSIONS = (("view_channel", "View Channel"), ("send_messages", "Send Messages"),
                        ("embed_links", "Embed Links"), ("attach_files", "Attach Files"))


class Poster:
    def __init__(self, client: discord.Client, cfg: dict):
        dc = cfg["discord"]
        self.client = client
        self.channels = {k: int(v or 0) for k, v in (dc.get("channels") or {}).items()}
        self.gap = float(dc.get("post_gap_seconds", 1.5))
        self.kev_role = int(dc.get("kev_ping_role_id") or 0)
        self.microsoft_role = int(dc.get("microsoft_ping_role_id") or 0)
        self.lock = asyncio.Lock()
        self._warned: set[str] = set()
        self.problems: dict[str, list[str]] = {}
        self.checked = False
        self._reported: dict[str, list[str]] | None = None

    async def _get(self, channel_id: int):
        channel = self.client.get_channel(channel_id)
        if channel is None:
            try:
                channel = await self.client.fetch_channel(channel_id)
            except discord.HTTPException as exc:
                log.error("can't access channel %s: %s", channel_id, exc)
                return None
        return channel

    async def load_overrides(self, store) -> None:
        if not hasattr(self, "configured"):
            self.configured = dict(self.channels)
        channels = dict(self.configured)
        for key, value in (await store.settings_get("channel:")).items():
            if str(value).isdigit():
                channels[key] = int(value)
        self.channels = channels

    async def set_channels(self, store, mapping: dict[str, int]) -> dict[str, list[str]]:
        for key, channel_id in mapping.items():
            await store.setting_set("channel:" + key, str(int(channel_id)))
            self.channels[key] = int(channel_id)
            self._warned.discard(key)
        return await self.validate_channels() if mapping else dict(self.problems)

    async def set_channel(self, store, key: str, channel_id: int | None) -> list[str]:
        if channel_id is None:
            await store.setting_delete("channel:" + key)
            self.channels[key] = getattr(self, "configured", self.channels).get(key, 0)
        else:
            await store.setting_set("channel:" + key, str(channel_id))
            self.channels[key] = int(channel_id)
        self._warned.discard(key)
        return (await self.validate_channels()).get(key, [])

    def overridden(self) -> set[str]:
        configured = getattr(self, "configured", self.channels)
        return {key for key, value in self.channels.items() if configured.get(key, 0) != value}

    def usable(self, key: str) -> bool:
        return bool(self.channels.get(key)) and key not in self.problems

    def health(self) -> list[tuple[str, int, str]]:
        out = []
        for key, channel_id in self.channels.items():
            if not channel_id:
                state = "unset"
            elif not self.checked:
                state = "unchecked"
            else:
                state = "; ".join(self.problems.get(key, [])) or "ok"
            out.append((key, channel_id, state))
        return out

    async def validate_channels(self) -> dict[str, list[str]]:
        problems: dict[str, list[str]] = {}
        for key, channel_id in self.channels.items():
            if not channel_id:
                continue
            channel = self.client.get_channel(channel_id)
            if channel is None:
                try:
                    channel = await self.client.fetch_channel(channel_id)
                except discord.HTTPException:
                    problems[key] = ["channel not found, or the bot can't see it"]
                    continue
            me = getattr(getattr(channel, "guild", None), "me", None)
            if me is None or not hasattr(channel, "permissions_for") or not hasattr(channel, "send"):
                problems[key] = ["not a server text channel"]
                continue
            granted = channel.permissions_for(me)
            missing = [f"missing {label}" for attr, label in REQUIRED_PERMISSIONS if not getattr(granted, attr, False)]
            if missing:
                problems[key] = missing
        self.problems = problems
        self.checked = True
        for key, issues in problems.items():
            for issue in issues:
                log.error("channel '%s' (ID %s): %s", key, self.channels[key], issue)
        if not problems:
            log.info("channel check: all %d configured channels are usable",
                     sum(1 for v in self.channels.values() if v))
        return problems

    async def report_channels(self) -> None:
        if self._reported == self.problems or not self.usable("log"):
            return
        self._reported = dict(self.problems)
        total = sum(1 for v in self.channels.values() if v)
        if not self.problems:
            await self.send("log", content=f"✅ Channel check: all {total} configured channels are usable.",
                            fallback=False)
            return
        lines = [f"• channel '{key}' (ID {self.channels[key]}): {issue}"
                 for key, issues in self.problems.items() for issue in issues]
        text = (f"⚠️ Channel check: {len(self.problems)} of {total} configured channels have problems. "
                "Posting to those keys is disabled until it is fixed.\n" + "\n".join(lines))
        await self.send("log", content=text[:1990], fallback=False)

    async def _resolve(self, key: str, fallback: bool):
        channel_id = self.channels.get(key) if key not in self.problems else 0
        if not channel_id and fallback and "default" not in self.problems:
            channel_id = self.channels.get("default")
        if not channel_id:
            if fallback and key not in self._warned:
                log.warning("no channel configured for '%s' (and no default) — those posts are dropped", key)
                self._warned.add(key)
            return None
        return await self._get(channel_id)

    def role_exists(self, role_id: int) -> bool:
        return any(guild.get_role(role_id) for guild in self.client.guilds)

    def check_roles(self) -> None:
        if self.microsoft_role and not self.role_exists(self.microsoft_role):
            log.warning("microsoft_ping_role_id %s doesn't match a role in any server the bot is in — "
                        "Microsoft update cards will be posted without a ping", self.microsoft_role)

    async def send(self, key: str, *, embed=None, content=None, ping_kev=False, fallback=True,
                   ping_microsoft=False, file: tuple[str, bytes] | None = None):
        await self.client.wait_until_ready()
        channel = await self._resolve(key, fallback)
        if channel is None:
            return None
        mentions = discord.AllowedMentions.none()
        if ping_kev and self.kev_role:
            content = f"<@&{self.kev_role}> {content or ''}".strip()
            mentions = discord.AllowedMentions(roles=[discord.Object(id=self.kev_role)])
        if ping_microsoft and self.microsoft_role and self.role_exists(self.microsoft_role):
            content = f"<@&{self.microsoft_role}> {content or ''}".strip()
            mentions = discord.AllowedMentions(roles=[discord.Object(id=self.microsoft_role)])
        attachment = discord.File(io.BytesIO(file[1]), filename=file[0]) if file else None
        async with self.lock:
            try:
                msg = await channel.send(content=content, embed=embed, allowed_mentions=mentions, file=attachment)
            except discord.HTTPException as exc:
                log.error("posting to '%s' failed: %s", key, exc)
                return None
            await asyncio.sleep(self.gap)
        return msg

    async def edit(self, channel_id: int, message_id: int, embed, *, file: tuple[str, bytes] | None = None) -> str:
        channel = await self._get(channel_id)
        if channel is None:
            return "gone"
        extra = {"attachments": [discord.File(io.BytesIO(file[1]), filename=file[0])]} if file else {}
        async with self.lock:
            try:
                await channel.get_partial_message(message_id).edit(embed=embed, **extra)
            except discord.NotFound:
                return "gone"
            except discord.HTTPException as exc:
                log.warning("edit %s/%s failed: %s", channel_id, message_id, exc)
                return "error"
            await asyncio.sleep(self.gap)
        return "ok"

    def jump_url(self, channel_id: int | None, message_id: int | None) -> str | None:
        if not channel_id or not message_id:
            return None
        guild = getattr(self.client.get_channel(channel_id), "guild", None)
        return f"https://discord.com/channels/{guild.id}/{channel_id}/{message_id}" if guild else None


def _chunks(text: str, limit: int = 3900) -> list[str]:
    out, buf = [], ""
    for line in text.split("\n"):
        if buf and len(buf) + len(line) + 1 > limit:
            out.append(buf)
            buf = ""
        buf = f"{buf}\n{line}" if buf else line
    return out + ([buf] if buf else [])


def is_admin(interaction: discord.Interaction) -> bool:
    perms = getattr(interaction.user, "guild_permissions", None)
    return bool(interaction.guild and perms and perms.administrator)


class ApplyLayoutView(discord.ui.View):
    def __init__(self, app, user_id: int, changes: int):
        super().__init__(timeout=300)
        self.app, self.user_id = app, user_id
        self.apply_button.label = f"Apply {changes} change{'s' if changes != 1 else ''}"

    @discord.ui.button(style=discord.ButtonStyle.danger, label="Apply")
    async def apply_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        if interaction.user.id != self.user_id or not is_admin(interaction):
            await interaction.response.send_message("Only the administrator who asked for this plan can apply it.",
                                                    ephemeral=True)
            return
        button.disabled = True
        self.stop()
        await interaction.response.edit_message(view=self)
        result = await layout.Applier(self.app, interaction.guild, self.app.cfg).apply()
        text = render.layout_result_text(result)
        for chunk in _chunks(text):
            await interaction.followup.send(embed=discord.Embed(description=chunk), ephemeral=True)
        await self.app.poster.send("log", embed=render.layout_log_embed(result), fallback=False)


def register_commands(tree: app_commands.CommandTree, app) -> None:
    async def source_autocomplete(interaction: discord.Interaction, current: str):
        return [app_commands.Choice(name=s.id, value=s.id)
                for s in app.sources if current.lower() in s.id.lower()][:25]

    @tree.command(name="status", description="Health of every feed source")
    async def status(interaction: discord.Interaction):
        states = {row["id"]: row for row in await app.store.all_sources()}
        embeds = render.status_embeds(app.sources, states)[:9] + [
            render.channels_embed(app.poster.health(), app.poster.overridden())]
        await interaction.response.send_message(embeds=embeds, ephemeral=True)

    @tree.command(name="cve", description="Show everything the bot has merged for a CVE / GHSA id")
    @app_commands.describe(vuln_id="e.g. CVE-2026-12345 or GHSA-xxxx-xxxx-xxxx")
    async def cve(interaction: discord.Interaction, vuln_id: str):
        vid = await app.store.vuln_resolve([vuln_id.strip()])
        row = await app.store.vuln_get(vid) if vid else None
        if not row:
            await interaction.response.send_message(f"`{vuln_id}` isn't tracked yet.", ephemeral=True)
            return
        await interaction.response.send_message(embed=render.vuln_embed(row["data"]))

    @tree.command(name="poll", description="Poll a source right now")
    @app_commands.default_permissions(manage_guild=True)
    @app_commands.autocomplete(source=source_autocomplete)
    async def poll(interaction: discord.Interaction, source: str):
        src = next((s for s in app.sources if s.id == source), None)
        if src is None:
            await interaction.response.send_message(f"No source called `{source}`.", ephemeral=True)
            return
        src.wake.set()
        await interaction.response.send_message(f"Polling `{source}` now — check `/status` in a minute.",
                                                ephemeral=True)

    @tree.command(name="kb", description="Show the stored card for a tracked Windows security update")
    @app_commands.describe(number="e.g. 5124008 or KB5124008")
    async def kb(interaction: discord.Interaction, number: str):
        kb_id = msrc.normalize_kb(number)
        row = await app.store.ms_kb_get(kb_id) if kb_id else None
        if not row:
            await interaction.response.send_message(f"`{number}` isn't a tracked Windows security update.",
                                                    ephemeral=True)
            return
        data = row["data"]
        attachment = discord.File(io.BytesIO(msrc.kb_tsv(data)), filename=msrc.tsv_name(kb_id))
        await interaction.response.send_message(embed=render.kb_embed(data), file=attachment)

    channel_group = app_commands.Group(name="channel", description="Where each category of post goes",
                                       default_permissions=discord.Permissions(manage_guild=True))

    async def category_autocomplete(interaction: discord.Interaction, current: str):
        return [app_commands.Choice(name=key, value=key)
                for key in app.poster.channels if current.lower() in key.lower()][:25]

    def category_state(key: str, issues: list[str]) -> str:
        channel_id = app.poster.channels.get(key)
        if not channel_id:
            return f"`{key}` is not set. Its posts go to the default channel (digests and log messages go nowhere)."
        if issues:
            return (f"`{key}` now points at <#{channel_id}>, but the bot can't use it: {'; '.join(issues)}. "
                    "Posting to it stays off until that is fixed; run `/channel check` afterwards.")
        return f"`{key}` now posts to <#{channel_id}>. Cards already posted stay where they are."

    @channel_group.command(name="set", description="Send a category of posts to a different channel")
    @app_commands.describe(category="The channel key, e.g. news, kev, microsoft, digest",
                           channel="The channel to post that category in")
    @app_commands.autocomplete(category=category_autocomplete)
    async def channel_set(interaction: discord.Interaction, category: str, channel: discord.TextChannel):
        if category not in app.poster.channels:
            await interaction.response.send_message(f"There is no category called `{category}`.", ephemeral=True)
            return
        await interaction.response.defer(ephemeral=True, thinking=True)
        issues = await app.poster.set_channel(app.store, category, channel.id)
        await interaction.followup.send(category_state(category, issues), ephemeral=True)

    @channel_group.command(name="reset", description="Put a category back on the channel from the config file")
    @app_commands.describe(category="The channel key to reset")
    @app_commands.autocomplete(category=category_autocomplete)
    async def channel_reset(interaction: discord.Interaction, category: str):
        if category not in app.poster.channels:
            await interaction.response.send_message(f"There is no category called `{category}`.", ephemeral=True)
            return
        await interaction.response.defer(ephemeral=True, thinking=True)
        issues = await app.poster.set_channel(app.store, category, None)
        await interaction.followup.send("Back to the config file's value. " + category_state(category, issues),
                                        ephemeral=True)

    @channel_group.command(name="list", description="Every category, its channel and whether the bot can post there")
    async def channel_list(interaction: discord.Interaction):
        embed = render.channels_embed(app.poster.health(), app.poster.overridden())
        await interaction.response.send_message(embed=embed, ephemeral=True)

    @channel_group.command(name="check", description="Re-check every channel's existence and permissions")
    async def channel_check(interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True, thinking=True)
        await app.poster.validate_channels()
        embed = render.channels_embed(app.poster.health(), app.poster.overridden())
        await interaction.followup.send(embed=embed, ephemeral=True)

    tree.add_command(channel_group)

    setup_group = app_commands.Group(name="setup", description="One-time server organisation",
                                     default_permissions=discord.Permissions(administrator=True))

    async def refuse(interaction: discord.Interaction) -> bool:
        if is_admin(interaction):
            return False
        await interaction.response.send_message("Only server administrators can use /setup.", ephemeral=True)
        return True

    @setup_group.command(name="layout", description="Plan the channel and category layout; nothing changes until you confirm")
    async def setup_layout(interaction: discord.Interaction):
        if await refuse(interaction):
            return
        await interaction.response.defer(ephemeral=True, thinking=True)
        stored = {k: int(v) for k, v in (await app.store.settings_get(layout.CATEGORY_PREFIX)).items()}
        resolved = dict(app.poster.channels)
        plan = layout.build_plan(app.cfg, interaction.guild, resolved, stored)
        chunks = _chunks(layout.render_plan(plan, resolved, interaction.guild))
        for index, chunk in enumerate(chunks):
            last = index == len(chunks) - 1
            view = ApplyLayoutView(app, interaction.user.id, plan.changes) if last and plan.changes else None
            kwargs = {"view": view} if view else {}
            await interaction.followup.send(embed=discord.Embed(description=f"```\n{chunk[:3980]}\n```"),
                                            ephemeral=True, **kwargs)

    @setup_group.command(name="rollback", description="Undo a /setup layout run from its snapshot")
    @app_commands.describe(run_id="The run id shown when the layout was applied, e.g. layout-20261005T120000Z")
    async def setup_rollback(interaction: discord.Interaction, run_id: str):
        if await refuse(interaction):
            return
        await interaction.response.defer(ephemeral=True, thinking=True)
        try:
            result = await layout.rollback(app, interaction.guild, run_id.strip())
        except layout.LayoutError as exc:
            await interaction.followup.send(str(exc), ephemeral=True)
            return
        text = f"Rolled back `{result['run_id']}`:\n" + "\n".join(f"• {d}" for d in result["done"])
        await interaction.followup.send(text[:1990], ephemeral=True)
        await app.poster.send("log", content=text[:1990], fallback=False)

    @setup_group.command(name="routes", description="How many recent items each route would move (changes nothing)")
    async def setup_routes(interaction: discord.Interaction):
        if await refuse(interaction):
            return
        await interaction.response.defer(ephemeral=True, thinking=True)
        rows = await layout.route_preview(app)
        await interaction.followup.send(embed=render.routes_embed(rows, 7), ephemeral=True)

    tree.add_command(setup_group)

    digest_group = app_commands.Group(name="digest", description="Intelligence digests",
                                      default_permissions=discord.Permissions(manage_guild=True))

    @digest_group.command(name="status", description="Next scheduled edition, last run and enabled editions")
    async def digest_status(interaction: discord.Interaction):
        runner = app.digest
        embed = render.digest_status_embed(
            enabled=bool(runner.cfg.get("enabled")), channel=runner.channel,
            channel_ok=app.poster.usable(runner.channel), upcoming=runner.upcoming(datetime.now(timezone.utc)),
            last=await app.store.digest_last())
        await interaction.response.send_message(embed=embed, ephemeral=True)

    @digest_group.command(name="now", description="Build an intelligence digest for the last N hours")
    @app_commands.describe(hours="Length of the window in hours (default 6)",
                           post="Post it to the digest channel instead of replying here",
                           private="Only show the reply to you")
    async def digest_now(interaction: discord.Interaction, hours: app_commands.Range[int, 1, 168] = 6,
                         post: bool = False, private: bool = False):
        await interaction.response.defer(ephemeral=post or private, thinking=True)
        built = await app.digest.build(float(hours), datetime.now(timezone.utc), "on-demand")
        if post:
            posted = await app.digest.post(built)
            note = f"Posted {posted} of {len(built.messages)} messages for run `{built.run_id}`." if posted else \
                f"Nothing was posted: the `{app.digest.channel}` channel is not set or failed the channel check."
            await interaction.followup.send(note, ephemeral=True)
            return
        for index, message in enumerate(built.messages[:10]):
            await interaction.followup.send(embed=render.digest_embed(built, message, index), ephemeral=private)

    tree.add_command(digest_group)

    @tree.command(name="entity", description="What the knowledge base knows about an actor, malware family or vendor")
    @app_commands.describe(name="e.g. APT29, Storm-2603, LockBit, Cobalt Strike", private="Only show the reply to you")
    async def entity(interaction: discord.Interaction, name: str, private: bool = False):
        found = app.kb.lookup(name)
        if not found:
            await interaction.response.send_message(f"`{name}` isn't in the knowledge base.", ephemeral=True)
            return
        await interaction.response.defer(ephemeral=private, thinking=True)
        days = int(app.cfg["digest"].get("entity_lookback_days", 14))
        mentions = await app.intel_mentions(found, days)
        await interaction.followup.send(embed=render.entity_embed(found, mentions, days), ephemeral=private)

    async def ticker_autocomplete(interaction: discord.Interaction, current: str):
        cur = current.strip().lower()
        return [app_commands.Choice(name=f"{sym} — {name}"[:100], value=sym)
                for sym, name in app.finance.watch.symbols().items()
                if cur in sym.lower() or cur in name.lower()][:25]

    @tree.command(name="stock", description="Latest quote and recent finance items for a watchlist ticker")
    @app_commands.describe(ticker="A ticker on the finance watchlist")
    @app_commands.autocomplete(ticker=ticker_autocomplete)
    async def stock(interaction: discord.Interaction, ticker: str):
        symbol = ticker.strip().upper().lstrip("$")
        if symbol not in app.finance.watch.symbols():
            await interaction.response.send_message(f"`{symbol}` isn't on the finance watchlist.", ephemeral=True)
            return
        await interaction.response.defer(thinking=True)
        quote = await app.store.quote_get(symbol)
        if (quote is None or time.time() - quote[1] > 900) and app.cfg["secrets"].get("finnhub_api_key"):
            try:
                q = await app.finnhub("/quote", symbol=symbol)
                if q and q.get("c"):
                    await app.store.quote_put(symbol, q)
                    quote = (q, int(time.time()))
            except Exception as exc:
                log.warning("live quote for %s failed: %s", symbol, exc)
        items = await app.store.fin_for_ticker(symbol, 5)
        await interaction.followup.send(
            embed=render.stock_embed(symbol, app.finance.watch.name(symbol), quote, items))

    async def event_type_autocomplete(interaction: discord.Interaction, current: str):
        from .events import EVENT_TYPES
        return [app_commands.Choice(name=t, value=t) for t in EVENT_TYPES if current.lower() in t.lower()][:25]

    @tree.command(name="study", description="Abnormal returns after a type of event (historical, not a forecast)")
    @app_commands.describe(type="Event type", window="Trading sessions after the event", ticker="Only this ticker")
    @app_commands.autocomplete(type=event_type_autocomplete)
    @app_commands.choices(window=[app_commands.Choice(name=f"{d} session{'s' if d > 1 else ''}", value=d)
                                  for d in (1, 5, 20)])
    async def study(interaction: discord.Interaction, type: str, window: int = 5, ticker: str | None = None):
        from .events import EVENT_TYPES
        from .study import WINDOW_BY_DAYS
        if type not in EVENT_TYPES or window not in WINDOW_BY_DAYS:
            await interaction.response.send_message(f"`{type}` isn't a known event type.", ephemeral=True)
            return
        await interaction.response.defer(thinking=True)
        result = await app.study.aggregate(type, WINDOW_BY_DAYS[window], ticker=ticker.upper() if ticker else None)
        await interaction.followup.send(embed=render.study_embed(result, window, ticker.upper() if ticker else None))

    @tree.command(name="events", description="Recorded events for a ticker")
    @app_commands.describe(ticker="e.g. CRWD", days="How far back (default 90)")
    async def events_cmd(interaction: discord.Interaction, ticker: str, days: app_commands.Range[int, 1, 1095] = 90):
        since = (datetime.now(timezone.utc) - timedelta(days=days)).date().isoformat()
        rows = await app.store.events_query(ticker=ticker.strip().upper(), since=since)
        await interaction.response.send_message(
            embed=render.events_embed(ticker.strip().upper(), days, rows, app.poster.jump_url))

    @tree.command(name="earnings", description="Upcoming earnings for the watchlist over the next 14 days")
    async def earnings(interaction: discord.Interaction):
        today = datetime.now(timezone.utc).date()
        rows = await app.store.earnings_between(today.isoformat(), (today + timedelta(days=14)).isoformat())
        await interaction.response.send_message(
            embed=render.earnings_embed(rows, app.finance.watch, "Upcoming earnings · next 14 days"))


class CyberRSSBotClient(discord.Client):
    def __init__(self, app):
        super().__init__(intents=discord.Intents.default())
        self.app = app
        self.tree = app_commands.CommandTree(self)
        app.poster = Poster(self, app.cfg)
        register_commands(self.tree, app)

    async def setup_hook(self) -> None:
        await self.app.start()
        await self.app.poster.load_overrides(self.app.store)
        guild_id = int(self.app.cfg["discord"].get("guild_id") or 0)
        if guild_id:
            guild = discord.Object(id=guild_id)
            self.tree.copy_global_to(guild=guild)
            await self.tree.sync(guild=guild)
        else:
            await self.tree.sync()
        self.app.launch_background()

    async def on_ready(self) -> None:
        log.info("logged in as %s — %d sources scheduled", self.user, len(self.app.sources))
        self.app.poster.check_roles()
        try:
            await self.app.poster.validate_channels()
            await self.app.poster.report_channels()
        except Exception:
            log.exception("channel check failed")

    async def close(self) -> None:
        await self.app.close()
        await super().close()
