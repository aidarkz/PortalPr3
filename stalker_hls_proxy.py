# stalker_hls_proxy.py – мультиисточниковый HLS‑прокси для нескольких Stalker‑порталов
# ---------------------------------------------------------------
# Изменения v5 (26 июн 2025)
#   • Исправлена обработка «кривых» ссылок в плейлистах, которые
#     выглядят как `%3A//hls/...` или содержат `://` без схемы.
#     Теперь они правильно нормализуются в абсолютный URL, и
#     404 на /segment/ больше не возникают.
# ---------------------------------------------------------------

from __future__ import annotations
import asyncio, httpx, logging, os, re, sys, time
from typing import Optional, Tuple, List
from urllib.parse import quote, urljoin, urlparse, unquote
from collections import OrderedDict, defaultdict

from fastapi import FastAPI, Response, Path
from starlette.responses import PlainTextResponse

# ---------------------------------------------------------------------------
# конфиг – правим только здесь
# ---------------------------------------------------------------------------
PORTALS: List[str] = [              # порядок – от «любимого» к запасным
    "ledir.thund.re",
    "stalker.ugoiptv.com:80",
]

MAC_POOL = [
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

MAX_CACHE_KEYS       = 10_000
MAX_CACHE_BYTES      = 150 * 2**20   # 150 MiB
SEGMENTS_PER_SESSION = 6
MIN_SWITCH_DELAY     = 4   # сек.
PLAYLIST_TTL         = 20
SEGMENT_TTL          = 8
HTTP_TIMEOUT         = 10

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
# LRU‑кеш url -> (body, expire_ts, status, size)
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
            self[key] = (body, exp, status, sz)
            log.debug("CACHE HIT  %s", key)
            return body, status

    async def put(self, key: str, body: bytes, ttl: int, status: int):
        if ttl <= 0:
            return
        now, sz = time.time(), len(body)
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
# состояние сессии – глобально на процесс (один экземпляр)
# ---------------------------------------------------------------------------
_current_sid: Optional[str] = None
_current_portal_idx: int    = 0
_seg_ok: int                = 0
_last_switch: float         = 0.0
_switch_lock                = asyncio.Lock()

# для каждого портала – свой индекс MAC’а, чтобы не банили пачкой
_mac_idx: defaultdict[str, int] = defaultdict(lambda: -1)

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _next_mac(host: str) -> str:
    _mac_idx[host] = (_mac_idx[host] + 1) % len(MAC_POOL)
    mac = MAC_POOL[_mac_idx[host]]
    log.info("HOST %s → MAC %s", host, mac)
    return mac

async def _fetch(url: str, *, ttl: int):
    cached = await _cache.get(url)
    if cached:
        return cached  # type: ignore
    try:
        r = await _http_client.get(url)
    except Exception:
        return b"", 599
    await _cache.put(url, r.content, ttl, r.status_code)
    return r.content, r.status_code

# ---------------------------------------------------------------------------
# playlist + переписывание сегментов
# ---------------------------------------------------------------------------
SEG_RX = re.compile(r"^(?!#)([^\r\n]+)", re.M)

async def _request_playlist(stream_id: str, start_idx: int) -> Tuple[str, bytes, int]:
    """Пытаемся открыть плейлист начиная с PORTALS[start_idx]"""
    portals_ring = PORTALS[start_idx:] + PORTALS[:start_idx]
    for p_idx, host in enumerate(portals_ring):
        play_url = f"http://{host}/play/live.php"
        for _ in range(len(MAC_POOL)):
            mac = _next_mac(host)
            qs  = f"mac={quote(mac)}&stream={stream_id}&extension=m3u8"
            url = f"{play_url}?{qs}"
            log.info("PLAYLIST <= %s", url)
            try:
                r = await _http_client.get(url)
            except Exception as exc:
                log.warning("request error: %s", exc)
                continue
            await _cache.put(str(r.url), r.content, PLAYLIST_TTL, r.status_code)
            if 200 <= r.status_code < 300:
                base = str(urlparse(str(r.url))._replace(query="", fragment="")).rsplit('/',1)[0] + '/'
                real_idx = (start_idx + p_idx) % len(PORTALS)
                log.info("PLAYLIST OK – host=%s idx=%s", host, real_idx+1)
                return base, r.content, real_idx
            log.warning("MAC %s @ %s → HTTP %s", mac, host, r.status_code)
    raise httpx.HTTPStatusError("No portal yielded 2xx", request=None, response=None)


def _rewrite(raw: str, *, base: str) -> str:
    """Переписать ссылки в плейлисте на локальный /segment/… с фиксами кривых ссылок."""

    def normalise(seg: str) -> str:
        seg = unquote(seg.strip())

        # 1) ссылки вида "%3A//hls/..." → "http://hls/..."
        if seg.startswith("://") or seg.startswith("%3A//"):
            seg = "http" + seg[2:]  # "http://hls/..."

        # 2) если содержит "://" но нет схемы – добавляем http://
        if not seg.startswith(("http://", "https://", "/")) and "://" in seg:
            seg = "http://" + seg.split("://", 1)[-1]
        return seg

    def repl(m: re.Match):
        seg = normalise(m.group(1))

        if seg.startswith("http://") or seg.startswith("https://"):
            full = seg
        elif seg.startswith("/"):
            u = urlparse(base)
            full = f"{u.scheme}://{u.netloc}{seg}"
        else:
            full = urljoin(base, seg)
        u = urlparse(full)
        return f"/segment/{u.scheme}/{u.netloc}{u.path}"

    return SEG_RX.sub(repl, raw)

async def _tick_segment(ok: bool):
    global _seg_ok, _last_switch
    if ok:
        _seg_ok += 1
    else:
        _seg_ok = SEGMENTS_PER_SESSION
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
        if _current_sid is not None:
            try:
                await _request_playlist(_current_sid, _current_portal_idx)
            except Exception as exc:
                log.warning("playlist switch failed: %s", exc)

# ---------------------------------------------------------------------------
# маршруты
# ---------------------------------------------------------------------------
@app.get("/playlist{portal_idx}.m3u8")
async def compat_numbered(portal_idx: int = Path(..., ge=1), *, stream_id: str):
    """Нумерованная точка входа – /playlist1.m3u8?stream_id=XYZ"""
    idx = (portal_idx - 1) % len(PORTALS)
    return PlainTextResponse(status_code=307,
        headers={"Location": f"/stream/{idx}/{stream_id}/index.m3u8"})

@app.get("/playlist.m3u8")
async def compat_default(stream_id: str):
    """Старый URL без номера использует портал‑0"""
    return PlainTextResponse(status_code=307,
        headers={"Location": f"/stream/0/{stream_id}/index.m3u8"})

@app.get("/stream/{portal_idx}/{sid}/index.m3u8")
async def playlist(portal_idx: int, sid: str):
    global _current_sid, _seg_ok, _last_switch, _current_portal_idx
    _current_sid        = sid
    _current_portal_idx = portal_idx % len(PORTALS)
    _seg_ok             = 0
    _last_switch        = time.time()
    try:
        base, raw, _current_portal_idx = await _request_playlist(sid, _current_portal_idx)
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
    log.info("Proxy ready: %s portals, playlist TTL=%ss, segment TTL=%ss", len(PORTALS), PLAYLIST_TTL, SEGMENT_TTL)
    import uvicorn
    uvicorn.run("stalker_hls_proxy:app", host=host, port=port)
