from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timedelta, timezone

import discord
from discord import app_commands

from . import render

log = logging.getLogger("cyberrssbot.discord")


class Poster:
    def __init__(self, client: discord.Client, cfg: dict):
        dc = cfg["discord"]
        self.client = client
        self.channels = {k: int(v or 0) for k, v in (dc.get("channels") or {}).items()}
        self.gap = float(dc.get("post_gap_seconds", 1.5))
        self.kev_role = int(dc.get("kev_ping_role_id") or 0)
        self.lock = asyncio.Lock()
        self._warned: set[str] = set()

    async def _get(self, channel_id: int):
        channel = self.client.get_channel(channel_id)
        if channel is None:
            try:
                channel = await self.client.fetch_channel(channel_id)
            except discord.HTTPException as exc:
                log.error("can't access channel %s: %s", channel_id, exc)
                return None
        return channel

    async def _resolve(self, key: str, fallback: bool):
        channel_id = self.channels.get(key) or (self.channels.get("default") if fallback else 0)
        if not channel_id:
            if fallback and key not in self._warned:
                log.warning("no channel configured for '%s' (and no default) — those posts are dropped", key)
                self._warned.add(key)
            return None
        return await self._get(channel_id)

    async def send(self, key: str, *, embed=None, content=None, ping_kev=False, fallback=True):
        await self.client.wait_until_ready()
        channel = await self._resolve(key, fallback)
        if channel is None:
            return None
        mentions = discord.AllowedMentions.none()
        if ping_kev and self.kev_role:
            content = f"<@&{self.kev_role}> {content or ''}".strip()
            mentions = discord.AllowedMentions(roles=[discord.Object(id=self.kev_role)])
        async with self.lock:
            try:
                msg = await channel.send(content=content, embed=embed, allowed_mentions=mentions)
            except discord.HTTPException as exc:
                log.error("posting to '%s' failed: %s", key, exc)
                return None
            await asyncio.sleep(self.gap)
        return msg

    async def edit(self, channel_id: int, message_id: int, embed) -> str:
        channel = await self._get(channel_id)
        if channel is None:
            return "gone"
        async with self.lock:
            try:
                await channel.get_partial_message(message_id).edit(embed=embed)
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
        await interaction.response.send_message(embeds=render.status_embeds(app.sources, states), ephemeral=True)

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

    async def close(self) -> None:
        await self.app.close()
        await super().close()
