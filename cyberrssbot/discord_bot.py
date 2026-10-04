from __future__ import annotations

import asyncio
import io
import logging
import time
from datetime import datetime, timedelta, timezone

import discord
from discord import app_commands

from . import msrc, render

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


def register_commands(tree: app_commands.CommandTree, app) -> None:
    async def source_autocomplete(interaction: discord.Interaction, current: str):
        return [app_commands.Choice(name=s.id, value=s.id)
                for s in app.sources if current.lower() in s.id.lower()][:25]

    @tree.command(name="status", description="Health of every feed source")
    async def status(interaction: discord.Interaction):
        states = {row["id"]: row for row in await app.store.all_sources()}
        embeds = render.status_embeds(app.sources, states)[:9] + [render.channels_embed(app.poster.health())]
        await interaction.response.send_message(embeds=embeds, ephemeral=True)

    @tree.command(name="cve", description="Show everything the bot has merged for a CVE / GHSA id")
    @app_commands.describe(vuln_id="e.g. CVE-2026-12345 or GHSA-xxxx-xxxx-xxxx")
    async def cve(interaction: discord.Interaction, vuln_id: str):
        vid = await app.store.vuln_resolve([vuln_id.strip()])
        row = await app.store.vuln_get(vid) if vid else None
        if not row:
            await interaction.response.send_message(f"`{vuln_id}` isn't tracked yet.", ephemeral=True)
            return
        await interaction.response.send_message(embed=render.vuln_embed(row["data"]), ephemeral=True)

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
        await interaction.response.send_message(embed=render.kb_embed(data), file=attachment, ephemeral=True)

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
                           post="Post it to the digest channel instead of previewing it privately")
    async def digest_now(interaction: discord.Interaction, hours: app_commands.Range[int, 1, 168] = 6,
                         post: bool = False):
        await interaction.response.defer(ephemeral=True, thinking=True)
        built = await app.digest.build(float(hours), datetime.now(timezone.utc), "on-demand")
        if post:
            posted = await app.digest.post(built)
            note = f"Posted {posted} of {len(built.messages)} messages for run `{built.run_id}`." if posted else \
                f"Nothing was posted: the `{app.digest.channel}` channel is not set or failed the channel check."
            await interaction.followup.send(note, ephemeral=True)
            return
        for index, message in enumerate(built.messages[:10]):
            await interaction.followup.send(embed=render.digest_embed(built, message, index), ephemeral=True)

    tree.add_command(digest_group)

    @tree.command(name="entity", description="What the knowledge base knows about an actor, malware family or vendor")
    @app_commands.describe(name="e.g. APT29, Storm-2603, LockBit, Cobalt Strike")
    async def entity(interaction: discord.Interaction, name: str):
        found = app.kb.lookup(name)
        if not found:
            await interaction.response.send_message(f"`{name}` isn't in the knowledge base.", ephemeral=True)
            return
        await interaction.response.defer(ephemeral=True, thinking=True)
        days = int(app.cfg["digest"].get("entity_lookback_days", 14))
        mentions = await app.intel_mentions(found, days)
        await interaction.followup.send(embed=render.entity_embed(found, mentions, days), ephemeral=True)

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
        await interaction.response.defer(ephemeral=True, thinking=True)
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
            embed=render.stock_embed(symbol, app.finance.watch.name(symbol), quote, items), ephemeral=True)

    @tree.command(name="earnings", description="Upcoming earnings for the watchlist over the next 14 days")
    async def earnings(interaction: discord.Interaction):
        today = datetime.now(timezone.utc).date()
        rows = await app.store.earnings_between(today.isoformat(), (today + timedelta(days=14)).isoformat())
        await interaction.response.send_message(
            embed=render.earnings_embed(rows, app.finance.watch, "Upcoming earnings · next 14 days"), ephemeral=True)


class CyberRSSBotClient(discord.Client):
    def __init__(self, app):
        super().__init__(intents=discord.Intents.default())
        self.app = app
        self.tree = app_commands.CommandTree(self)
        app.poster = Poster(self, app.cfg)
        register_commands(self.tree, app)

    async def setup_hook(self) -> None:
        await self.app.start()
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
