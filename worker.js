/**
 * Cloudflare Worker: ретранслятор для Telegram + диагностика.
 *
 * /apiws?dst=<host>:<port>  — WebSocket-релей на сырой TCP
 * /diag                    — HTTP-диагностика connect() и fetch(), обычный GET
 * /healthz                 — просто 200
 *
 * БЕЛОЙ СПИСОК ОБЯЗАТЕЛЕН. Без него это open-proxy на инфраструктуре
 * Cloudflare: через него можно сканировать порты и бить по чужому аккаунту,
 * и Cloudflare его забанит.
 */

// БЕЗ ЭТОЙ СТРОКИ connect() не определён и релей не заработает.
import { connect } from "cloudflare:sockets";

const ALLOWED_HOSTS = new Set([
  "api.telegram.org",
  "149.154.166.110",
]);

const ALLOWED_PORTS = new Set([443]);

function parseDst(raw) {
  if (!raw) return null;
  const idx = raw.lastIndexOf(":");
  if (idx <= 0) return null;
  const hostname = raw.slice(0, idx).toLowerCase();
  const port = Number(raw.slice(idx + 1));
  if (!hostname || !Number.isInteger(port)) return null;
  if (!ALLOWED_HOSTS.has(hostname)) return null;
  if (!ALLOWED_PORTS.has(port)) return null;
  return { hostname, port };
}

function toBytes(data) {
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (typeof data === "string") return new TextEncoder().encode(data);
  if (data && typeof data.arrayBuffer === "function") {
    return data.arrayBuffer().then((ab) => new Uint8Array(ab));
  }
  return new Uint8Array();
}

function closeWs(ws, code, reason) {
  try {
    ws.close(code, String(reason).slice(0, 120));
  } catch {
    /* уже закрыт */
  }
}

function describe(e) {
  if (!e) return "unknown error";
  const msg = e.message || String(e);
  const name = e.name || "";
  return `${name}: ${msg}`.replace(/\s+/g, " ").slice(0, 300);
}

export default {
  async fetch(request) {
    const url = new URL(request.url);

    // ── диагностика ────────────────────────────────────────────────────
    if (url.pathname === "/diag") {
      return await this.diag();
    }

    if (url.pathname === "/healthz") {
      return new Response("ok");
    }

    if (url.pathname !== "/apiws") {
      return new Response("Not found", { status: 404 });
    }

    const upgrade = (request.headers.get("Upgrade") || "").toLowerCase();
    if (upgrade !== "websocket") {
      return new Response("Expected websocket", { status: 426 });
    }

    const dst = parseDst(url.searchParams.get("dst"));
    if (!dst) {
      return new Response("dst not allowed", { status: 403 });
    }

    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    server.accept();

    let socket;
    let writer;
    try {
      socket = connect({ hostname: dst.hostname, port: dst.port });
      // ВАЖНО: писать через socket.writable.write() НЕЛЬЗЯ — такого метода
      // в рантайме нет. Только через getWriter(), как в примере из доков.
      writer = socket.writable.getWriter();
    } catch (e) {
      const why = describe(e);
      console.error(`connect(${dst.hostname}:${dst.port}) failed: ${why}`);
      closeWs(server, 1011, `connect: ${why}`);
      return new Response(null, { status: 101, webSocket: client });
    }

    // ВАЖНО: ответ 101 уходит наружу НЕМЕДЛЕННО, не дожидаясь TCP-соединения.
    // Если ждать socket.opened перед ответом, холодный старт изолята Cloudflare
    // подвешивает рукопожатие на десятки секунд — клиент успевает отвалиться
    // по таймауту. Поэтому соединение поднимаем уже ПОСЛЕ ответа.
    (async () => {
      try {
        await socket.opened;
      } catch (e) {
        const why = describe(e);
        console.error(`socket.opened failed (${dst.hostname}:${dst.port}): ${why}`);
        try {
          socket.close();
        } catch {}
        closeWs(server, 1011, `connect: ${why}`);
        return;
      }

      socket.closed.catch((e) => console.error(`socket closed: ${describe(e)}`));

      // TCP -> WebSocket
      (async () => {
        try {
          const reader = socket.readable.getReader();
          while (true) {
            const { value, done } = await reader.read();
            if (done || !value) break;
            server.send(value);
          }
        } catch (e) {
          console.error(`tcp->ws: ${describe(e)}`);
        } finally {
          try {
            socket.close();
          } catch {}
          closeWs(server, 1001, "upstream closed");
        }
      })();

      // WebSocket -> TCP
      let dead = false;
      server.addEventListener("message", async (event) => {
        if (dead) return;
        try {
          await writer.write(await toBytes(event.data));
        } catch (e) {
          const why = describe(e);
          console.error(`ws->tcp: ${why}`);
          dead = true;
          closeWs(server, 1011, `write: ${why}`);
        }
      });

      for (const ev of ["close", "error"]) {
        server.addEventListener(ev, () => {
          dead = true;
          try {
            socket.close();
          } catch {}
        });
      }
    })();

    return new Response(null, { status: 101, webSocket: client });
  },

  /**
   * Показывает, что именно умеет и не умеет аккаунт.
   * Открывается обычным браузером или curl — WebSocket не нужен.
   */
  async diag() {
    const lines = [];

    // 1. connect() к Telegram
    try {
      const s = connect({ hostname: "api.telegram.org", port: 443 });
      try {
        await Promise.race([
          s.opened,
          new Promise((_, rej) => setTimeout(() => rej(new Error("таймаут 8с")), 8000)),
        ]);
        lines.push("connect(api.telegram.org:443)  = OK  ✅  сырой TCP работает");
        try { s.close(); } catch {}
      } catch (e) {
        lines.push(`connect(api.telegram.org:443)  = FAIL  ❌  ${describe(e)}`);
        try { s.close(); } catch {}
      }
    } catch (e) {
      lines.push(`connect(api.telegram.org:443)  = FAIL  ❌  ${describe(e)}`);
    }

    // 2. connect() к постороннему хосту — отличаем "запрещён тарифом" от "запрещён адрес".
    //    Порт 443, а не 80: Cloudflare намеренно не пускает connect() на HTTP-порты.
    try {
      const s = connect({ hostname: "example.com", port: 443 });
      try {
        await Promise.race([
          s.opened,
          new Promise((_, rej) => setTimeout(() => rej(new Error("таймаут 8с")), 8000)),
        ]);
        lines.push("connect(example.com:443)        = OK  ✅  значит connect() доступен");
        try { s.close(); } catch {}
      } catch (e) {
        lines.push(`connect(example.com:443)        = FAIL  ❌  ${describe(e)}`);
        try { s.close(); } catch {}
      }
    } catch (e) {
      lines.push(`connect(example.com:443)        = FAIL  ❌  ${describe(e)}`);
    }

    // 3. fetch() к Telegram — работает на любом тарифе
    try {
      const r = await fetch("https://api.telegram.org/bot0:0/getMe", {
        signal: AbortSignal.timeout(8000),
      });
      const body = (await r.text()).slice(0, 120);
      lines.push(`fetch(api.telegram.org)         = HTTP ${r.status}  ${body}`);
    } catch (e) {
      lines.push(`fetch(api.telegram.org)         = FAIL  ❌  ${describe(e)}`);
    }

    return new Response(lines.join("\n"), {
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  },
};
