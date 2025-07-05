# stalker_hls_proxy.py – мультисессионный HLS‑прокси для одного или нескольких Stalker‑порталов
# ---------------------------------------------------------------------------
# Изменения v6 (27 июн 2025)
#   • _rewrite() добавил нормализацию «кривых» сегментов (%3A//, :// без схемы,
#     двойные слеши и т.п.) ⇒ 404 больше не встречаются.
#   • Перешёл от ГЛОБАЛЬНЫХ счётчиков к per‑stream state ⇒ несколько клиентов
#     могут смотреть разные каналы параллельно без взаимного влияния.
#   • Чёткое разделение «плохих» HTTP‑кодов (407/458/512/451/405) и сетевых
#     ошибок – на них просто берётся следующий MAC.
# ---------------------------------------------------------------------------

from __future__ import annotations
import asyncio, httpx, logging, re, sys, time
from collections import OrderedDict, defaultdict
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote, unquote, urljoin, urlparse, urlunparse

from fastapi import FastAPI, Path, Response
from starlette.responses import PlainTextResponse

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------
PORTALS: List[str] = [
    "ledir.thund.re",
    "stalker.ugoiptv.com:80",
]

MAC_POOL = [
    "00:1A:79:00:0A:2C", "00:1A:79:1A:04:B7", "00:1A:79:C5:94:26",
    "00:1A:79:02:13:52", "00:1A:79:B9:81:75", "00:1A:79:02:59:77",
    "00:1A:79:73:16:62", "00:1A:79:C6:E5:E9", "00:1A:79:00:09:7E",
    "00:1A:79:22:5A:77", "00:1A:79:74:4E:C7",
]

MAX_CACHE_KEYS  = 10_000
MAX_CACHE_BYTES = 150 * 2**20  # 150 MiB
PLAYLIST_TTL    = 20           # s
SEGMENT_TTL     = 8            # s
SEG_OK_LIMIT    = 6            # ts before optional reswitch
MIN_SWITCH_SEC  = 4
HTTP_TIMEOUT    = 10
BAD_CODES       = {407, 458, 451, 512, 405}

# ---------------------------------------------------------------------------
app = FastAPI()
log = logging.getLogger("stalker_hls_proxy")
logging.basicConfig(format="%(asctime)s [%(levelname)s] %(message)s",
                    datefmt="%H:%M:%S", level=logging.INFO)

_client = httpx.AsyncClient(timeout=HTTP_TIMEOUT,
                             headers={"User-Agent": "Mozilla/5.0 (Qt; STB/1.0)"},
                             follow_redirects=True)

# ---------------------------------------------------------------------------
# LRU cache  url → (body, expire_ts, status, size)
# ---------------------------------------------------------------------------
class LRU(OrderedDict[str, Tuple[bytes, float, int, int]]):
    def __init__(self):
        super().__init__(); self.max_k = MAX_CACHE_KEYS; self.max_b = MAX_CACHE_BYTES
        self.now_b = 0;     self.lock = asyncio.Lock()

    async def get(self, k: str):
        async with self.lock:
            rec = self.pop(k, None)
            if not rec: return None
            body, exp, st, sz = rec
            if exp < time.time():
                self.now_b -= sz; return None
            self[k] = (body, exp, st, sz)  # touch
            return body, st

    async def put(self, k: str, body: bytes, ttl: int, st: int):
        if ttl <= 0: return
        async with self.lock:
            old = self.pop(k, None)
            if old: self.now_b -= old[3]
            sz = len(body)
            self[k] = (body, time.time()+ttl, st, sz); self.now_b += sz
            while self.now_b>self.max_b or len(self)>self.max_k:
                _, (_,_,_,s) = self.popitem(last=False); self.now_b -= s

_cache = LRU()

# ---------------------------------------------------------------------------
# per‑portal MAC index – чтобы разные порталы не банили пачкой
# ---------------------------------------------------------------------------
_mac_pos: defaultdict[str,int] = defaultdict(lambda:-1)

def next_mac(host: str) -> str:
    _mac_pos[host] = (_mac_pos[host]+1) % len(MAC_POOL)
    mac = MAC_POOL[_mac_pos[host]]
    log.info("HOST %s → MAC %s", host, mac)
    return mac

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
async def fetch(url: str, *, ttl: int):
    cached = await _cache.get(url)
    if cached: return cached  # type: ignore
    try:
        r = await _client.get(url)
    except Exception:
        return b"", 599
    await _cache.put(url, r.content, ttl, r.status_code)
    return r.content, r.status_code

SEG_RE = re.compile(r"^(?!#)([^\r\n]+)", re.M)

# ---------------------------------------------------------------------------
# ► Per‑stream session state
# ---------------------------------------------------------------------------
class Session:
    def __init__(self):
        self.portal_idx = 0
        self.seg_ok = 0
        self.last_switch = 0.0
        self.base_url = ""
        self.lock = asyncio.Lock()

sessions: Dict[str, Session] = defaultdict(Session)  # sid -> Session()

# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------
async def obtain_playlist(sid: str, start_idx: int) -> Tuple[str, bytes, int]:
    portals_chain = PORTALS[start_idx:] + PORTALS[:start_idx]
    for offs, host in enumerate(portals_chain):
        play_url = f"http://{host}/play/live.php"
        for _ in range(len(MAC_POOL)):
            mac = next_mac(host)
            q   = f"mac={quote(mac)}&stream={sid}&extension=m3u8"
            url = f"{play_url}?{q}"
            log.info("PLAYLIST <= %s", url)
            try:
                r = await _client.get(url)
            except Exception as e:
                log.warning("network err: %s", e); continue
            await _cache.put(str(r.url), r.content, PLAYLIST_TTL, r.status_code)
            if 200<=r.status_code<300:
                pr = urlparse(str(r.url))._replace(query="", fragment="")
                base = urlunparse(pr) if str(r.url).endswith('/') else urlunparse(pr).rsplit('/',1)[0] + '/'
                idx = (start_idx+offs) % len(PORTALS)
                log.info("PLAYLIST OK – host=%s idx=%s", host, idx)
                return base, r.content, idx
            if r.status_code in BAD_CODES:
                log.warning("MAC %s → HTTP %s (skip)", mac, r.status_code); continue
            log.warning("MAC %s → unexpected HTTP %s", mac, r.status_code)
    raise httpx.HTTPStatusError("No working MAC", request=None, response=None)

# -- link normaliser --------------------------------------------------------

def normalise(seg: str) -> str:
    seg = unquote(seg.strip())
    if seg.startswith("%3A//"):          # "%3A//hls/..."
        seg = "http" + seg[2:]
    if seg.startswith("://"):
        seg = "http" + seg               # “://hls/…”
    if "//" in seg and not seg.startswith(("http://","https://","/")):
        # "hls.domain.com/p.ts" with schema stripped
        seg = "http://" + seg.split("//",1)[-1]
    return seg


def rewrite_m3u8(text: str, *, base: str) -> str:
    def repl(m: re.Match):
        seg = normalise(m.group(1))
        full = seg if seg.startswith(("http://","https://")) else urljoin(base, seg)
        u = urlparse(full)
        return f"/segment/{u.scheme}/{u.netloc}{u.path}"
    return SEG_RE.sub(repl, text)

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.get("/playlist{idx}.m3u8")
async def entry_numbered(idx: int = Path(..., ge=1), *, stream_id: str):
    return PlainTextResponse(status_code=307,
        headers={"Location": f"/stream/{idx-1}/{stream_id}/index.m3u8"})

@app.get("/playlist.m3u8")
async def entry_default(stream_id: str):
    return PlainTextResponse(status_code=307,
        headers={"Location": f"/stream/0/{stream_id}/index.m3u8"})

@app.get("/stream/{portal_idx}/{sid}/index.m3u8")
async def playlist(portal_idx: int, sid: str):
    sess = sessions[sid]
    sess.portal_idx = portal_idx % len(PORTALS)
    sess.seg_ok = 0; sess.last_switch = time.time()
    try:
        base, raw, sess.portal_idx = await obtain_playlist(sid, sess.portal_idx)
    except httpx.HTTPStatusError as exc:
        return PlainTextResponse(f"playlist error: {exc}", status_code=502)
    sess.base_url = base
    return Response(rewrite_m3u8(raw.decode(errors="ignore"), base=base),
                    media_type="application/vnd.apple.mpegurl")

@app.get("/segment/{proto}/{path:path}")
async def segment(proto: str, path: str):
    url = f"{proto}://{path}"
    body, st = await fetch(url, ttl=SEGMENT_TTL)
    # try to map back to sid from path (last numeric part before _.ts)
    maybe_sid = path.split('/')[-1].split('_')[0]
    sess = sessions.get(maybe_sid)
    if sess:
        ok = 200<=st<300
        sess.seg_ok = sess.seg_ok+1 if ok else SEG_OK_LIMIT
        if sess.seg_ok>=SEG_OK_LIMIT and time.time()-sess.last_switch>MIN_SWITCH_SEC:
            async with sess.lock:
                if sess.seg_ok>=SEG_OK_LIMIT and time.time()-sess.last_switch>MIN_SWITCH_SEC:
                    log.info("=== switching playlist (sid=%s) after %s segments ===", maybe_sid, sess.seg_ok)
                    sess.seg_ok = 0; sess.last_switch = time.time()
                    try:
                        await obtain_playlist(maybe_sid, sess.portal_idx)
                    except Exception as e:
                        log.warning("reswitch failed: %s", e)
    return Response(body, media_type="video/MP2T", status_code=st)

# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    host="0.0.0.0"; port=int(sys.argv[1]) if len(sys.argv)>1 else 8080
    log.info("Proxy ready: %s portals, playlist TTL=%ss, segment TTL=%ss", len(PORTALS), PLAYLIST_TTL, SEGMENT_TTL)
    uvicorn.run("stalker_hls_proxy:app", host=host, port=port)
