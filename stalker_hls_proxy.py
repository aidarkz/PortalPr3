# stalker_hls_proxy.py – улучшенный прокси‑адаптер для Stalker‑портала
# ---------------------------------------------------------------
# Изменения v3 (26 июн 2025)
#   • base для сегментов строится корректно через urlparse/urlunparse
#     ⇒ больше нет путей вида "/segment///hls/...".
#   • коды 407 и 458 теперь явно считаются «плохими» – переходим к
#     следующему MAC без подсчёта ошибки.
#   • детализированы логи («HTTP 407 → proxy‑auth required»).
# ---------------------------------------------------------------

from __future__ import annotations
import asyncio, httpx, logging, os, re, sys, time
from typing import Optional, Tuple
from urllib.parse import quote, urljoin, urlparse, urlunparse
from collections import OrderedDict

from fastapi import FastAPI, Response
from starlette.responses import PlainTextResponse

# ---------------------------------------------------------------------------
# конфиг
# ---------------------------------------------------------------------------
PORTAL_HOST          = "ledir.thund.re"
PORTAL_PLAY_URL      = f"http://{PORTAL_HOST}/play/live.php"

MAC_POOL             = [
    "00:1A:79:00:0A:2C",
    "00:1A:79:1A:04:B7",
    "00:1A:79:C5:94:26",
    "00:1A:79:02:13:52",
    "00:1A:79:B9:81:75",
    "00:1A:79:02:59:77",
    "00:1A:79:73:16:62",
    "00:1A:79:C6:E5:E9",
    "00:1A:79:00:09:7E",
    "00:1A:79:22:5A:77",
    "00:1A:79:74:4E:C7",
]

MAX_CACHE_KEYS       = 10_000          # элементов в LRU
MAX_CACHE_BYTES      = 150 * 2**20     # 150 MiB
SEGMENTS_PER_SESSION = 6               # TS подряд одним MAC
MIN_SWITCH_DELAY     = 4               # сек. между сменами MAC
PLAYLIST_TTL         = 20              # сек.
SEGMENT_TTL          = 8               # сек.
HTTP_TIMEOUT         = 10              # сек.

# ---------------------------------------------------------------------------
app = FastAPI()
log = logging.getLogger("stalker_hls_proxy")
logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
    level=logging.INFO,
)

_http_client = httpx.AsyncClient(
    timeout=HTTP_TIMEOUT,
    headers={
        "User-Agent": "Mozilla/5.0 (QtEmbedded; U) AppleWebKit/533.3 (KHTML, like Gecko) STB/1.0",
    },
    follow_redirects=True,
)

# ---------------------------------------------------------------------------
# LRU‑кеш – url -> (body, expire_ts, status, size)
# ---------------------------------------------------------------------------
class LRUCache(OrderedDict[str, Tuple[bytes, float, int, int]]):
    def __init__(self, max_keys: int, max_bytes: int):
        super().__init__()
        self._max_keys  = max_keys
        self._max_bytes = max_bytes
        self._bytes_now = 0
        self._lock = asyncio.Lock()

    async def get(self, key: str):
        now = time.time()
        async with self._lock:
            rec = self.pop(key, None)
            if not rec:
                return None
            body, exp, status, sz = rec
            if exp < now:
                self._bytes_now -= sz
                return None
            self[key] = (body, exp, status, sz)  # LRU touch
            log.debug("CACHE HIT  %s", key)
            return body, status

    async def put(self, key: str, body: bytes, ttl: int, status: int):
        if ttl <= 0:
            return
        now = time.time()
        sz  = len(body)
        async with self._lock:
            old = self.pop(key, None)
            if old:
                self._bytes_now -= old[3]
            self[key] = (body, now + ttl, status, sz)
            self._bytes_now += sz
            await self._evict()
            log.debug("CACHE MISS %s (stored, %dkB)", key, sz//1024)

    async def _evict(self):
        while self._bytes_now > self._max_bytes or len(self) > self._max_keys:
            _, (_, _, _, sz) = self.popitem(last=False)
            self._bytes_now -= sz

_cache = LRUCache(MAX_CACHE_KEYS, MAX_CACHE_BYTES)

# ---------------------------------------------------------------------------
# состояние сессии
# ---------------------------------------------------------------------------
_last_switch: float           = 0.0
_seg_ok:       int             = 0
_current_sid: Optional[str]    = None
_mac_idx:      int             = -1
_switch_lock                    = asyncio.Lock()

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _next_mac() -> str:
    global _mac_idx
    _mac_idx = (_mac_idx + 1) % len(MAC_POOL)
    mac = MAC_POOL[_mac_idx]
    log.info("→ MAC %s", mac)
    return mac

async def _fetch(url: str, *, ttl: int):
    cached = await _cache.get(url)
    if cached:
        return cached  # type: ignore
    try:
        r = await _http_client.get(url)
    except Exception:
        return b"", 599  # network error
    await _cache.put(url, r.content, ttl, r.status_code)
    return r.content, r.status_code

# ---------------------------------------------------------------------------
# playlist + rewrite
# ---------------------------------------------------------------------------
SEG_RX = re.compile(r"^(?!#)([^\r\n]+)", re.M)

BAD_CODES = {407, 458, 451, 512, 405}

def _build_base(final_url: str) -> str:
    pr = urlparse(final_url)
    pr = pr._replace(query="", params="", fragment="")
    clean = urlunparse(pr)
    if not clean.endswith('/'):
        clean = clean.rsplit('/', 1)[0] + '/'
    return clean

async def _request_playlist(stream_id: str) -> Tuple[str, bytes]:
    """Перебираем MAC‑адреса, пока не получим 2xx"""
    for _ in range(len(MAC_POOL)):
        mac = _next_mac()
        qs  = f"mac={quote(mac)}&stream={stream_id}&extension=m3u8"
        url = f"{PORTAL_PLAY_URL}?{qs}"
        log.info("PLAYLIST <= %s", url)
        try:
            r = await _http_client.get(url)
        except Exception as exc:
            log.warning("network err: %s", exc)
            continue
        await _cache.put(str(r.url), r.content, PLAYLIST_TTL, r.status_code)
        if 200 <= r.status_code < 300:
            base = _build_base(str(r.url))
            log.info("PLAYLIST OK – base: %s", base)
            return base, r.content
        if r.status_code in BAD_CODES:
            log.warning("MAC %s → HTTP %s (skip)", mac, r.status_code)
            continue
        log.warning("MAC %s → unexpected HTTP %s", mac, r.status_code)
    raise httpx.HTTPStatusError("All MACs failed", request=None, response=None)


def _rewrite(raw: str, *, base: str) -> str:
    def repl(m: re.Match):
        seg = m.group(1)
        full = urljoin(base, seg)
        u = urlparse(full)
        return f"/segment/{u.scheme}/{u.netloc}{u.path}"
    return SEG_RX.sub(repl, raw)

async def _tick_segment(ok: bool):
    global _seg_ok, _last_switch
    if ok:
        _seg_ok += 1
    else:
        _seg_ok = SEGMENTS_PER_SESSION  # форсированная смена
    if _seg_ok < SEGMENTS_PER_SESSION:
        return
    if time.time() - _last_switch < MIN_SWITCH_DELAY:
        return
    async with _switch_lock:
        if _seg_ok < SEGMENTS_PER_SESSION:
            return
        log.info("=== switching playlist after %s segments ===", _seg_ok)
        _seg_ok = 0
        _last_switch = time.time()
        if _current_sid:
            try:
                await _request_playlist(_current_sid)
            except Exception as exc:
                log.warning("playlist switch failed: %s", exc)

# ---------------------------------------------------------------------------
# routes
# ---------------------------------------------------------------------------

@app.get("/playlist.m3u8")
async def compat(stream_id: str):
    return PlainTextResponse(status_code=307, headers={"Location": f"/stream/{stream_id}/index.m3u8"})

@app.get("/stream/{sid}/index.m3u8")
async def playlist(sid: str):
    global _seg_ok, _last_switch, _current_sid
    _seg_ok = 0
    _last_switch = time.time()
    _current_sid = sid
    try:
        base, raw = await _request_playlist(sid)
    except httpx.HTTPStatusError as exc:
        return PlainTextResponse(f"playlist error: {exc}", status_code=502)
    text = raw.decode(errors="ignore")
    return Response(_rewrite(text, base=base), media_type="application/vnd.apple.mpegurl")

@app.get("/segment/{proto}/{path:path}")
async def segment(proto: str, path: str):
    url = f"{proto}://{path}"
    body, status = await _fetch(url, ttl=SEGMENT_TTL)
    await _tick_segment(200 <= status < 300)
    return Response(body, media_type="video/MP2T", status_code=status)

# ---------------------------------------------------------------------------
if __name__ == "__main__":
    host = "0.0.0.0"
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    log.info("Proxy ready: playlist TTL=%ss segment TTL=%ss", PLAYLIST_TTL, SEGMENT_TTL)
    import uvicorn
    uvicorn.run("stalker_hls_proxy:app", host=host, port=port)
