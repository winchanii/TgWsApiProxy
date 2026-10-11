# tgwsapiproxy

Локальный прокси для **Telegram-ботов** в РФ. Тот же приём, что в
[tg-ws-proxy](https://github.com/Flowseal/tg-ws-proxy), но вместо MTProto
Telegram Desktop — обычный HTTPS Bot API.

```
Telegram Bot ──► tgwsapiproxy ──► Cloudflare Worker ──► api.telegram.org
                  127.0.0.1        workers.dev
                  socks5 + http CONNECT
```

DPI на участке между тобой и Cloudflare видит только `SNI=xxx.workers.dev`.
`SNI=api.telegram.org` не покидает туннель — его открывает сам бот, уже внутри.

**Ноль зависимостей.** Только стандартная библиотека. Нужно потому, что PyPI
бывает недоступен из РФ, а `aiohttp-socks`/`httpx-socks`/`PySocks` туда не поставить.

---

## Установка

С PyPI:

```bash
pip install tgwsapiproxy
```

Прямо из репозитория (без публикации на PyPI):

```bash
pip install "git+https://github.com/winchanii/TgWsApiProxy"
```

Опционально, вместе с библиотеками ботов:

```bash
pip install "tgwsapiproxy[aiogram]"    # aiogram + aiohttp-socks
pip install "tgwsapiproxy[ptb]"        # python-telegram-bot + httpx[socks]
```

> Пока пакет не опубликован на PyPI, работает только вариант с `git+...`.

## Настройка Cloudflare Worker

Нужен бесплатный аккаунт на [dash.cloudflare.com](https://dash.cloudflare.com/).
Домен покупать не нужно.

1. `Compute` → `Workers & Pages` → `Create application` → `Start with Hello World!` → `Deploy`
2. `Edit code` — вставь `worker.js` (лежит в sdist этого пакета) → `Deploy`
3. Скопируй домен вида `my-worker-abc123.имя.workers.dev`

### Важно: белый список

`worker.js` жёстко ограничен списком `ALLOWED_HOSTS`. **Не убирай его.**
Без ограничения получится open-proxy на инфраструктуре Cloudflare: через него
можно сканировать порты и бить по чужому аккаунту, и Cloudflare его забанит.

## Запуск

```bash
tgwsapiproxy --worker-host my-worker-abc123.workers.dev
```

Поднимает два входа:

| Порт | Протокол | Для кого |
|------|----------|----------|
| `1080` | SOCKS5 | клиенты с поддержкой SOCKS5 |
| `8080` | HTTP CONNECT | всё, что умеет HTTP-прокси |

По умолчанию разрешён только `api.telegram.org`, слушает только `127.0.0.1`.

## Использование в боте

### aiogram 3

```python
from aiogram import Bot
from aiogram.client.session.aiohttp import AiohttpSession

session = AiohttpSession(proxy="http://127.0.0.1:8080")
bot = Bot(token="123456:ABC", session=session)
```

> В aiogram 3.31 класс называется `AiohttpSession`. `AioHTTPSession` — имя
> из ранних 3.x, сейчас не существует.

**aiogram требует `aiohttp-socks` при любом типе прокси** — хоть `socks5://`,
хоть `http://`. Это зашито в его код: `_prepare_connector()` импортирует
`ProxyConnector` из `aiohttp_socks` безусловно.

### python-telegram-bot 20+

```python
from telegram import Bot
from telegram.request import HTTPXRequest

bot = Bot(token="123456:ABC", request=HTTPXRequest(proxy="http://127.0.0.1:8080"))
```

PTB работает на httpx, у которого HTTP-прокси поддержан нативно — дополнительные
пакеты не нужны.

### Встроенный прокси прямо в боте

Пакет умеет поднимать прокси сам, отдельным процессом не нужен:

```python
import asyncio
from aiogram import Bot
from aiogram.client.session.aiohttp import AiohttpSession
import tgwsapiproxy

async def main():
    async with tgwsapiproxy.run_proxy("my-worker.workers.dev"):
        session = AiohttpSession(proxy=tgwsapiproxy.proxy_url())   # http://127.0.0.1:8080
        bot = Bot(token="123456:ABC", session=session)
        await dp.start_polling(bot)
```

Неблокирующий вариант — `start_proxy()` / `stop_proxy()`.

---

## Проверка

```bash
curl -sS --proxy http://127.0.0.1:8080 https://api.telegram.org/bot<ТОКЕН>/getMe
```

JSON с `"ok": true` — туннель живой.

---

## Как это работает

Ключевая идея: **SOCKS5 оперирует байтами TCP и ничего не шифрует.**
TLS-сессию до `api.telegram.org` открывает сам бот, уже внутри туннеля.
Поэтому `SNI=api.telegram.org` физически не может утечь на участок между
тобой и Cloudflare: там видно только `SNI=xxx.workers.dev`.

Cloudflare соединяется с Telegram от своего имени, уже не из России, где
блокировки и DPI не действуют.

---

## Публикация на PyPI

Публикация привязана к GitHub Releases — токен API не нужен, авторизацию
делает GitHub через OIDC.

1. На <https://pypi.org/manage/account/publishing/> добавь издателя:
   - Owner: `winchanii`
   - Repository name: `TgWsApiProxy`
   - Workflow name: `publish.yml`
   - Environment name: `pypi`
2. В GitHub: `Settings` → `Environments` → создай окружение `pypi`
3. Создай релиз: `Releases` → `Draft a new release` → тег `v0.1.0` → `Publish release`

Workflow соберёт пакет, проверит метаданные через `twine check` и загрузит
артефакты на PyPI.

> Имя `tgwsapiproxy` на PyPI необратимо. Перед первой публикацией убедись,
> что оно свободно: <https://pypi.org/project/tgwsapiproxy/> должен вернуть 404.

---

## Ограничения и риски

**Надёжность ~85–95% на бесплатном тарифе Workers.** `connect()` от Worker'а
к Telegram периодически провисает на десятки секунд. Клиент делает до четырёх
попыток с растущим бэкоффом, это поднимает успех с ~70% до ~90%, но остаток
уходит на платный тариф — там TCP-исходящие стабильнее. **Ботам всё равно
нужен собственный ретрай** поверх этого: нормальная практика для сетевого
вызова в любом случае.

**Рукопожатие с Worker провисает на холодных стартах изолятов.** Здоровый
хендшейк занимает ~0.3 с, таймаут на попытку намеренно небольшой (10 с),
иначе повторы не успевают отработать за бюджет клиента.

**Cloudflare может забанить аккаунт.** Использование CF как транспорта для
обхода блокировок местами противоречит их ToS. Держи аккаунт на отдельной почте.

**Это не VPN.** Только SOCKS5/HTTP на localhost с белым списком. Интернет,
YouTube, Discord не починятся — для этого нужен Xray/sing-box.

**Лимиты Workers.** Бесплатного тарифа хватает для работы ботов (текст, фото,
документы). На массовую выкачку видео — уже нет.

**Длинные соединения.** Keepalive-пинг каждые 25 с не даёт Cloudflare закрыть
простаивый WebSocket. Для long polling с `timeout=30` хватает с запасом.

---

## Лицензия

MIT
