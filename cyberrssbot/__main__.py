from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from logging.handlers import RotatingFileHandler

from .app import App, run_check
from .config import load_config


def main() -> None:
    parser = argparse.ArgumentParser(prog="cyberrssbot", description="Cybersecurity feed bot for Discord")
    parser.add_argument("-c", "--config", default="config.yaml")
    parser.add_argument("--check", action="store_true",
                        help="fetch every source once, print health, post nothing")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--log-file", metavar="PATH",
                        help="log to a rotating file instead of stderr (needed under pythonw / a scheduled task)")
    args = parser.parse_args()

    handlers = None
    if args.log_file:
        handlers = [RotatingFileHandler(args.log_file, maxBytes=5_000_000, backupCount=3, encoding="utf-8")]
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, handlers=handlers,
                        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    logging.getLogger("discord").setLevel(logging.WARNING)

    cfg = load_config(args.config)
    if args.check:
        sys.exit(asyncio.run(run_check(cfg)))

    token = cfg["secrets"]["discord_token"]
    if not token:
        sys.exit("DISCORD_TOKEN is not set. Copy .env.example to .env and fill it in.")

    from .discord_bot import CyberRSSBotClient
    CyberRSSBotClient(App(cfg)).run(token, log_handler=None)


if __name__ == "__main__":
    main()
