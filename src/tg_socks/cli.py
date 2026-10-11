"""CLI-точка входа для tg-socks."""

from __future__ import annotations

import argparse
import asyncio
import sys

import tg_socks


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="tg-socks",
        description=(
            "Локальный SOCKS5/HTTP-прокси через Cloudflare Worker — "
            "доступ к Telegram Bot API из РФ без VPN."
        ),
    )
    p.add_argument(
        "--worker-host",
        required=True,
        help="домен твоего Cloudflare Worker, напр. my-worker.workers.dev",
    )
    p.add_argument(
        "--worker-port",
        type=int,
        default=443,
        help="порт Worker (для тестов или self-hosted релея)",
    )
    p.add_argument(
        "--worker-ip",
        help="подключаться по этому IP, но слать SNI домена (только для тестов)",
    )
    p.add_argument(
        "--listen-host",
        default="127.0.0.1",
        help="интерфейс прослушивания (по умолчанию только локально)",
    )
    p.add_argument("--listen-port", type=int, default=1080, help="порт SOCKS5")
    p.add_argument(
        "--http-port",
        type=int,
        default=8080,
        help="порт HTTP CONNECT-прокси; 0 — выключить",
    )
    p.add_argument(
        "--allow",
        nargs="*",
        default=["api.telegram.org"],
        help="белый список целей; пустой список разрешает всё (осторожно)",
    )
    p.add_argument("--ca", help="путь к CA-сертификату (для self-signed в тестах)")
    p.add_argument(
        "--insecure",
        action="store_true",
        help="НЕ проверять сертификат Worker (небезопасно, только для отладки)",
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="таймаут рукопожатия с Worker на одну попытку, сек (по умолчанию 10)",
    )
    p.add_argument(
        "--retry-delay",
        type=float,
        default=1.0,
        help="база бэкоффа между попытками, сек (растёт кратно номеру попытки)",
    )
    p.add_argument("-v", "--verbose", action="store_true", help="подробный лог")
    return p


def main(argv: list[str] | None = None) -> int:
    cfg = build_parser().parse_args(argv)
    tg_socks._VERBOSE = cfg.verbose

    if cfg.allow and "api.telegram.org" not in cfg.allow:
        tg_socks.log("внимание: api.telegram.org не в белом списке — бот работать не будет")

    try:
        asyncio.run(tg_socks.amain(cfg))
    except KeyboardInterrupt:
        tg_socks.log("\nостановлено")
    return 0


if __name__ == "__main__":
    sys.exit(main())
