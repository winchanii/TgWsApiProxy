#!/usr/bin/env python3
"""
tgwsapiproxy — локальный SOCKS5-прокси, который заворачивает трафик в WebSocket
и отправляет через Cloudflare Worker к Telegram. Обход блокировки без VPN.

    Telegram Bot  ──socks5://127.0.0.1:1080──▶  Cloudflare Worker  ──▶ api.telegram.org

Почему это работает: SOCKS5 оперирует байтами TCP и ничего не шифрует.
TLS-сессию до api.telegram.org открывает сам бот, уже ВНУТРИ туннеля.
Поэтому SNI=api.telegram.org физически не может утечь на участок сети
между тобой и Cloudflare — там видно только SNI=xxx.workers.dev.

Только стандартная библиотека. Python 3.11+.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import os
import ssl
import struct
import sys
import time
from urllib.parse import quote

# ── константы протокола ────────────────────────────────────────────────────

WS_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

OP_CONT, OP_TEXT, OP_BIN, OP_CLOSE, OP_PING, OP_PONG = 0x0, 0x1, 0x2, 0x8, 0x9, 0xA

SOCKS_OK = 0x00
SOCKS_FAIL = 0x01
SOCKS_NOT_ALLOWED = 0x02
SOCKS_HOST_UNREACH = 0x04

PING_EVERY = 25.0  # сек. Cloudflare любит закрывать простаивающие WS
READ_SIZE = 65536

# Рукопожатие с Worker на холодных стартах изолятов Cloudflare изредка
# провисает на десятки секунд. Здоровый хендшейк занимает ~0.3с, поэтому
# таймаут намеренно небольшой: иначе не успевают отработать повторы —
# один зависший на 40с коннект съедает весь бюджет клиента.
RETRIES_ATTEMPTS = 4

# ── логи ───────────────────────────────────────────────────────────────────

_VERBOSE = False


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def vlog(msg: str) -> None:
    if _VERBOSE:
        log(msg)


# ── WebSocket поверх TLS ───────────────────────────────────────────────────


def _mask(payload: bytes) -> bytes:
    """XOR с 4-байтовой маской через big-int — это C-speed, а не цикл в Python."""
    n = len(payload)
    if n == 0:
        return b""
    key = os.urandom(4)
    key_stream = (key * (n // 4 + 1))[:n]
    masked = int.from_bytes(payload, "big") ^ int.from_bytes(key_stream, "big")
    return key + masked.to_bytes(n, "big")


def build_frame(opcode: int, payload: bytes) -> bytes:
    """Клиентские кадры WebSocket обязаны быть замаскированы (RFC 6455 §5.3)."""
    n = len(payload)
    header = bytearray([0x80 | opcode])  # FIN=1
    if n < 126:
        header.append(0x80 | n)
    elif n < 65536:
        header.append(0x80 | 126)
        header += struct.pack("!H", n)
    else:
        header.append(0x80 | 127)
        header += struct.pack("!Q", n)
    return bytes(header) + _mask(payload)


class WSError(Exception):
    pass


class WSConn:
    """Минимальный WebSocket-клиент: binary-фреймы туда и обратно + keepalive."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, rest: bytes):
        self.reader = reader
        self.writer = writer
        self.buf = rest  # хвост ответа на хендшейк
        self.closed = False
        self._lock = asyncio.Lock()

    # --- handshake ---

    @classmethod
    async def connect(
        cls,
        host: str,
        port: int,
        path: str,
        ctx: ssl.SSLContext,
        connect_ip: str | None = None,
    ) -> "WSConn":
        # connect_ip — подключиться по IP, но сохранить SNI/Host домена
        reader, writer = await asyncio.open_connection(
            connect_ip or host, port, ssl=ctx, server_hostname=host
        )

        key = base64.b64encode(os.urandom(16)).decode()
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "User-Agent: Mozilla/5.0\r\n"
            "\r\n"
        )
        writer.write(req.encode())
        await writer.drain()

        head = b""
        while b"\r\n\r\n" not in head:
            chunk = await reader.read(4096)
            if not chunk:
                raise WSError("соединение закрыто на хендшейке")
            head += chunk

        header, _, rest = head.partition(b"\r\n\r\n")
        lines = header.decode("latin-1").split("\r\n")
        status = lines[0]

        if "101" not in status:
            detail = next((l for l in lines if l.lower().startswith("x-cf-") or "error" in l.lower()), "")
            raise WSError(f"хендшейк отклонён: {status} {detail}")

        # Проверка, что сервер — честный WS, а не кто-то ещё
        expected = base64.b64encode(hashlib.sha1(key.encode() + WS_GUID).digest()).decode()
        got = next(
            (l.split(":", 1)[1].strip() for l in lines if l.lower().startswith("sec-websocket-accept")),
            None,
        )
        if got != expected:
            raise WSError("Sec-WebSocket-Accept не совпал")

        return cls(reader, writer, rest)

    # --- приём ---

    async def _read(self, n: int) -> bytes:
        if n <= 0:
            return b""
        if self.buf:
            data, self.buf = self.buf[:n], self.buf[n:]
            if len(data) == n:
                return data
            return data + await self.reader.readexactly(n - len(data))
        return await self.reader.readexactly(n)

    async def recv(self) -> tuple[int, bytes]:
        """Читает кадр. Прозрачно отвечает на ping. Возвращает (opcode, payload)."""
        while True:
            b = await self._read(2)
            opcode = b[0] & 0x0F
            masked = b[1] & 0x80
            ln = b[1] & 0x7F
            if ln == 126:
                ln = struct.unpack("!H", await self._read(2))[0]
            elif ln == 127:
                ln = struct.unpack("!Q", await self._read(8))[0]

            mask_key = await self._read(4) if masked else b""
            data = await self._read(ln)

            if masked:
                data = bytes(x ^ mask_key[i % 4] for i, x in enumerate(data))

            if opcode == OP_PING:
                await self.send_raw(OP_PONG, data)
                continue
            if opcode == OP_PONG:
                continue
            return opcode, data

    # --- отправка ---

    async def send_raw(self, opcode: int, payload: bytes = b"") -> None:
        async with self._lock:
            self.writer.write(build_frame(opcode, payload))
            await self.writer.drain()

    async def send(self, data: bytes) -> None:
        await self.send_raw(OP_BIN, data)

    async def ping(self) -> None:
        await self.send_raw(OP_PING, os.urandom(4))

    async def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        try:
            await self.send_raw(OP_CLOSE, struct.pack("!H", 1000))
        except Exception:
            pass
        try:
            self.writer.close()
        except Exception:
            pass


# ── SOCKS5 ─────────────────────────────────────────────────────────────────


def socks_reply(code: int) -> bytes:
    # VER REP RSV ATYP=IPv4 BND.ADDR BND.PORT — с заглушкой 0.0.0.0:0
    return bytes([0x05, code, 0x00, 0x01]) + b"\x00" * 6


async def handle_socks(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    cfg: argparse.Namespace,
    ctx: ssl.SSLContext,
) -> None:
    peer = writer.get_extra_info("peername")
    label = f"{peer[0]}:{peer[1]}" if peer else "?"

    try:
        # --- приветствие ---
        if await reader.readexactly(1) != b"\x05":
            writer.write(socks_reply(SOCKS_FAIL))
            await writer.drain()
            return

        n_methods = (await reader.readexactly(1))[0]
        methods = await reader.readexactly(n_methods)
        if 0x00 not in methods:  # NO AUTH
            writer.write(bytes([0x05, 0xFF]))
            await writer.drain()
            log(f"{label}: нет подходящего метода авторизации")
            return

        writer.write(b"\x05\x00")
        await writer.drain()

        # --- запрос ---
        ver, cmd, _rsv, atyp = await reader.readexactly(4)
        if ver != 0x05 or cmd != 0x01:  # CONNECT
            writer.write(socks_reply(SOCKS_FAIL))
            await writer.drain()
            return

        if atyp == 0x01:
            host = socket_inet_ntoa(await reader.readexactly(4))
        elif atyp == 0x03:
            # домен в SOCKS5 — это ASCII; codecs "idna" не умеет error-handler,
            # поэтому декодируем в utf-8 с заменой невалидных байт
            host = (await reader.readexactly((await reader.readexactly(1))[0])).decode("utf-8", "replace")
        else:
            writer.write(socks_reply(SOCKS_FAIL))
            await writer.drain()
            return

        port = struct.unpack("!H", await reader.readexactly(2))[0]

        if cfg.allow and host not in cfg.allow:
            writer.write(socks_reply(SOCKS_NOT_ALLOWED))
            await writer.drain()
            log(f"{label}: ЗАПРЕЩЕНО целевое назначение {host}:{port}")
            return

        # --- туннель через Worker ---
        dst = f"{host}:{port}"
        ws = await open_tunnel(host, port, cfg, ctx)
        if ws is None:
            writer.write(socks_reply(SOCKS_HOST_UNREACH))
            await writer.drain()
            return

        writer.write(socks_reply(SOCKS_OK))
        await writer.drain()
        log(f"{label}: туннель открыт → {dst}")

        await pump(reader, writer, ws, label, dst)

    except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
        pass
    except Exception as e:  # noqa: BLE001 — не роняем сервер из-за одного клиента
        log(f"{label}: ошибка: {e!r}")
    finally:
        try:
            writer.close()
        except Exception:
            pass


def socket_inet_ntoa(raw: bytes) -> str:
    return ".".join(str(b) for b in raw)


async def open_tunnel(
    host: str,
    port: int,
    cfg: argparse.Namespace,
    ctx: ssl.SSLContext,
    attempt: int = 0,
) -> WSConn | None:
    """
    Поднимает туннель к host:port через Worker. None — если не вышло.

    Рукопожатие с Worker изредка провисает на холодных стартах изолятов
    Cloudflare, поэтому делаем RETRIES_ATTEMPTS попыток: одна удачная
    из трёх — норма для этой схемы, клиенту её не видно.
    """
    dst = f"{host}:{port}"
    last = ""

    for attempt in range(1, RETRIES_ATTEMPTS + 1):
        try:
            return await asyncio.wait_for(
                WSConn.connect(
                    cfg.worker_host, cfg.worker_port, f"/apiws?dst={quote(dst)}", ctx, cfg.worker_ip
                ),
                timeout=cfg.timeout,
            )
        except asyncio.TimeoutError:
            last = "таймаут рукопожатия с Worker"
        except (OSError, WSError, ssl.SSLError) as e:
            last = repr(e)

        if attempt < RETRIES_ATTEMPTS:
            vlog(f"попытка {attempt}/{RETRIES_ATTEMPTS} не удалась ({last}), повторяю")
            await asyncio.sleep(cfg.retry_delay * attempt)  # растущий бэкофф

    log(f"Worker недоступен после {RETRIES_ATTEMPTS} попыток ({dst}): {last}")
    return None


async def handle_http_connect(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    cfg: argparse.Namespace,
    ctx: ssl.SSLContext,
) -> None:
    """
    HTTP CONNECT прокси — для клиентов без поддержки SOCKS5.

    aiohttp, httpx и requests умеют HTTP-прокси из коробки, а SOCKS5 требует
    отдельной библиотеки (aiohttp-socks / httpx-socks / PySocks), которую в РФ
    невозможно поставить: PyPI недоступен. Поэтому тут дублирующий вход.
    """
    peer = writer.get_extra_info("peername")
    label = f"http {peer[0]}:{peer[1]}" if peer else "http ?"

    try:
        line = (await reader.readline()).decode("latin-1").strip()
        parts = line.split()
        if len(parts) != 3 or parts[0].upper() != "CONNECT":
            writer.write(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
            return

        target = parts[1]
        host, _, port_s = target.rpartition(":")
        if not host:
            host, port_s = target, "443"
        port = int(port_s)

        # съедаем остальные заголовки запроса
        while True:
            h = await reader.readline()
            if h in (b"\r\n", b"\n", b""):
                break

        if cfg.allow and host not in cfg.allow:
            writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
            log(f"{label}: ЗАПРЕЩЕНО {host}:{port}")
            return

        ws = await open_tunnel(host, port, cfg, ctx)
        if ws is None:
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
            return

        writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        await writer.drain()
        log(f"{label}: туннель открыт → {host}:{port}")
        await pump(reader, writer, ws, label, f"{host}:{port}")

    except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
        pass
    except Exception as e:  # noqa: BLE001
        log(f"{label}: ошибка: {e!r}")
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def pump(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    ws: WSConn,
    label: str,
    dst: str,
) -> None:
    """Гоняет байты в обе стороны + пингует, чтобы Cloudflare не закрыл простаивающий WS."""

    # Разрыв соединения — это нормальная часть жизни туннеля, а не ошибка.
    # Без этого фильтра asyncio сыплет "Task exception was never retrieved"
    # в лог на каждый чих и бот утонет в мусоре.
    TEARDOWN = (
        asyncio.IncompleteReadError,
        ConnectionResetError,
        ConnectionAbortedError,
        BrokenPipeError,
        TimeoutError,
        ssl.SSLError,
        OSError,
    )

    async def guarded(coro, name: str) -> None:
        try:
            await coro
        except asyncio.CancelledError:
            raise
        except TEARDOWN as e:
            vlog(f"{label}: {name} — штатный разрыв ({e!r})")
        except Exception as e:  # noqa: BLE001
            log(f"{label}: {name} — неожиданная ошибка: {e!r}")

    async def client_to_ws() -> None:
        while True:
            data = await client_reader.read(READ_SIZE)
            if not data:
                break
            await ws.send(data)

    async def ws_to_client() -> None:
        while True:
            opcode, data = await ws.recv()
            if opcode == OP_CLOSE:
                break
            if opcode == OP_BIN and data:
                client_writer.write(data)
                await client_writer.drain()

    async def keepalive() -> None:
        while True:
            await asyncio.sleep(PING_EVERY)
            await ws.ping()

    tasks = [
        asyncio.create_task(guarded(client_to_ws(), "клиент→Worker")),
        asyncio.create_task(guarded(ws_to_client(), "Worker→клиент")),
        asyncio.create_task(guarded(keepalive(), "keepalive")),
    ]
    try:
        # кто первый завершился — тот закрывает соединение
        _done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        # gather по ВСЕМ задачам, иначе исключения из "done" теряются
        await asyncio.gather(*tasks, return_exceptions=True)
    finally:
        await ws.close()
        log(f"{label}: туннель закрыт → {dst}")


def build_ssl_context(ca_file: str | None, insecure: bool) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=ca_file) if ca_file else ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def amain(cfg: argparse.Namespace) -> None:
    ctx = build_ssl_context(cfg.ca, cfg.insecure)

    servers = [
        await asyncio.start_server(
            lambda r, w: handle_socks(r, w, cfg, ctx),
            cfg.listen_host,
            cfg.listen_port,
            reuse_address=True,
        )
    ]
    log(f"слушаю socks5://{cfg.listen_host}:{cfg.listen_port}")

    if cfg.http_port:
        servers.append(
            await asyncio.start_server(
                lambda r, w: handle_http_connect(r, w, cfg, ctx),
                cfg.listen_host,
                cfg.http_port,
                reuse_address=True,
            )
        )
        log(f"слушаю http://{cfg.listen_host}:{cfg.http_port} (CONNECT)")

    log(f"Worker: {cfg.worker_host}:{cfg.worker_port}  (путь /apiws)")
    log(f"разрешено: {', '.join(sorted(cfg.allow)) if cfg.allow else 'любые хосты'}")
    log(f"ping каждые {PING_EVERY:.0f}с · Ctrl-C для выхода\n")

    async with servers[0]:
        for s in servers:
            await s.serve_forever()


# ── публичный API ──────────────────────────────────────────────────────────

__version__ = "0.1.0"

__all__ = [
    "run_proxy",
    "proxy_url",
    "start_proxy",
    "stop_proxy",
    "WSConn",
    "WSError",
    "__version__",
]


class _Config:
    """Конфиг для программного API (без argparse)."""

    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)


def proxy_url(scheme: str = "http", host: str = "127.0.0.1", port: int = 8080) -> str:
    """Готовый прокси-URL для клиента бота.

        proxy_url()                          → http://127.0.0.1:8080
        proxy_url("socks5", port=1080)       → socks5://127.0.0.1:1080
    """
    return f"{scheme}://{host}:{port}"


async def start_proxy(cfg) -> list:
    """Поднимает прокси и возвращает серверы. Не блокирует."""
    global _VERBOSE
    _VERBOSE = cfg.verbose

    ctx = build_ssl_context(cfg.ca, cfg.insecure)
    servers = [
        await asyncio.start_server(
            lambda r, w: handle_socks(r, w, cfg, ctx),
            cfg.listen_host,
            cfg.listen_port,
            reuse_address=True,
        )
    ]
    log(f"tgwsapiproxy: SOCKS5 на {cfg.listen_host}:{cfg.listen_port}")

    if cfg.http_port:
        servers.append(
            await asyncio.start_server(
                lambda r, w: handle_http_connect(r, w, cfg, ctx),
                cfg.listen_host,
                cfg.http_port,
                reuse_address=True,
            )
        )
        log(f"tgwsapiproxy: HTTP CONNECT на {cfg.listen_host}:{cfg.http_port}")

    log(f"tgwsapiproxy: Worker {cfg.worker_host}, разрешено: {', '.join(cfg.allow) or 'всё'}")
    return servers


async def stop_proxy(servers: list) -> None:
    """Гасит серверы, полученные от start_proxy()."""
    for s in servers:
        s.close()
        try:
            await asyncio.wait_for(s.wait_closed(), timeout=2)
        except Exception:
            pass


async def run_proxy(
    worker_host: str,
    *,
    listen_host: str = "127.0.0.1",
    socks_port: int = 1080,
    http_port: int = 8080,
    allow: list[str] | None = None,
    timeout: float = 10.0,
    retry_delay: float = 1.0,
    worker_port: int = 443,
    worker_ip: str | None = None,
    ca: str | None = None,
    insecure: bool = False,
    verbose: bool = False,
) -> None:
    """Поднимает прокси и блокирует, пока он работает.

        async with run_proxy("my-worker.workers.dev"):
            ...
    """
    cfg = _Config(
        worker_host=worker_host,
        worker_port=worker_port,
        worker_ip=worker_ip,
        listen_host=listen_host,
        listen_port=socks_port,
        http_port=http_port,
        allow=list(allow if allow is not None else ["api.telegram.org"]),
        ca=ca,
        insecure=insecure,
        timeout=timeout,
        retry_delay=retry_delay,
        verbose=verbose,
    )
    servers = await start_proxy(cfg)
    try:
        await asyncio.Event().wait()
    finally:
        await stop_proxy(servers)
