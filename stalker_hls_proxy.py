# stalker_hls_proxy.py – лёгкая сборка (memory‑friendly) + AuthToken‑портал
# ---------------------------------------------------------------------------
# Изменения v8.6 (07 июл 2025)
#   • **FIX** SyntaxError в rewrite_m3u8 (скобка не закрыта).
#   • AuthToken добавляется как обычный параметр (`AuthToken=<tok>`), без трюков.
#   • 204 No Content → BAD_CODES, плейлисту нужен **200** и ненулевое тело.
# ---------------------------------------------------------------------------

from __future__ import annotations
import asyncio, httpx, logging, re, sys, time
from collections import OrderedDict, defaultdict
from typing import Dict, List, Tuple
from urllib.parse import quote, urlencode, unquote, urljoin, urlparse, urlunparse

from fastapi import FastAPI, Path, Response
from starlette.responses import PlainTextResponse

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------
PORTALS: List[str] = [
    "ledir.thund.re",
    "stalker.ugoiptv.com:80",
    "93.119.105.61:80",
    "clientportal.com:2095",
    "foxx.pure-iptv.net:80",  # portal‑5 – с AuthToken
]

# MAC‑пулы --------------------------------------------------------------
MAC_POOLS: Dict[str, List[str]] = {
    "ledir.thund.re": [
        "00:1A:79:00:0A:2C", "00:1A:79:1A:04:B7", "00:1A:79:C5:94:26",
        "00:1A:79:02:13:52", "00:1A:79:B9:81:75",
    ],
    "stalker.ugoiptv.com:80": [
        "00:1A:79:32:53:16", "00:1A:79:79:F2:42", "00:1A:79:00:1C:5B",
        "00:1A:79:00:18:51", "00:1A:79:B1:66:BD", "00:1A:79:00:11:DE",
        "00:1A:79:42:DA:30", "00:1A:79:31:61:31", "00:1A:79:B3:91:AA",
        "00:1A:79:B6:5F:F0",  "00:1A:79:E6:F9:FC", "00:1A:79:C1:1B:1A",
        "00:1A:79:C2:7A:0F", "00:1A:79:BF:90:B0", "00:1A:79:7E:19:2B",
        "00:1A:79:32:C5:93", "00:1A:79:E8:63:0C", "00:1A:79:7E:A9:DC",
        "00:1A:79:B7:B4:EB", "00:1A:79:71:F3:B0", "00:1A:79:0E:33:7D",
        "00:1A:79:13:2C:FD",
    ],
    "93.119.105.61:80": [
        "00:1A:79:4D:F6:60", "00:1A:79:13:8F:5A", "00:1A:79:00:1F:2B",
        "00:1A:79:B0:64:C2", "00:1A:79:00:40:EF", "00:1A:79:00:27:C5",
        "00:1A:79:00:27:C4", "00:1A:79:4D:6F:C6", "00:1A:79:B5:B1:C2",
    ],
    "clientportal.com:2095": [
        "00:1A:79:4D:F6:60", "00:1A:79:13:8F:5A", "00:1A:79:00:1F:2B",
        "00:1A:79:B0:64:C2", "00:1A:79:00:40:EF", "00:1A:79:00:27:C5",
        "00:1A:79:00:27:C4", "00:1A:79:4D:6F:C6", "00:1A:79:B5:B1:C2",
    ],
}

# foxx.pure‑iptv.net: постоянные AuthToken
AUTH_TOKENS: Dict[str, str] = {
    "00:1A:79:AC:76:38": "99E271197A32250B0F8DCAA0E9E3A4EA",
    "00:1A:79:C1:92:57": "9727A2E9CC67AA6E67A2A8D25C29EFA5",
    "00:1A:79:6A:3C:19": "7E8FB7840E9F9E60E9E070FE6482E793",
}

DEFAULT_MAC_POOL: List[str] = [
    "00:1A:79:00:0A:2C", "00:1A:79:1A:04:B7", "00:1A:79:C5:94:26",
    "00:1A:79:02:13:52", "00:1A:79:B9:81:75", "00:1A:79:02:59:77",
    "00:1A:79:73:16:62", "00:1A:79:C6:E5:E9",
]

MAX_CACHE_KEYS  = 10_000
MAX_CACHE_BYTES = 50 * 2**20
PLAYLIST_TTL    = 10
SEGMENT_TTL     = 4
SEG_OK_LIMIT    = 6
MIN_SWITCH_SEC  = 4
HTTP_TIMEOUT    = 10
BAD_CODES       = {204, 405, 407, 451, 458, 512}
SESSION_IDLE_S  = 30

# ---------------------------------------------------------------------------
app = FastAPI()
log = logging.getLogger("stalker_hls_proxy")
logging.basicConfig(format="%(asctime)s [%(levelname)s] %(message)s",
                    datefmt="%H:%M:%S", level=logging.INFO)

_client = httpx.AsyncClient(timeout=HTTP_TIMEOUT,
    headers={"User-Agent": "Mozilla/5.0 (Qt; STB/1.0)"},
    follow_redirects=True)

# ---------------------------------------------------------------------------
class LRU(OrderedDict[str, Tuple[bytes, float, int, int]]):
    def __init__(self):
        super().__init__(); self.max_k=MAX_CACHE_KEYS; self.max_b=MAX_CACHE_BYTES
        self.now_b=0; self.lock=asyncio.Lock()
    async def get(self,k):
        async with self.lock:
            rec=self.pop(k,None)
            if not rec: return None
            body,exp,st,sz=rec
            if exp<time.time(): self.now_b-=sz; return None
            self[k]=(body,exp,st,sz); return body,st
    async def put(self,k,b,ttl,st):
        if ttl<=0: return
        async with self.lock:
            old=self.pop(k,None)
            if old: self.now_b-=old[3]
            sz=len(b); self[k]=(b,time.time()+ttl,st,sz); self.now_b+=sz
            while self.now_b>self.max_b or len(self)>self.max_k:
                _,(_,_,_,s)=self.popitem(last=False); self.now_b-=s
_cache=LRU()

_mac_pos: defaultdict[str,int]=defaultdict(lambda:-1)

def _pool(host:str)->List[str]:
    if host=="foxx.pure-iptv.net:80":
        return list(AUTH_TOKENS)
    return MAC_POOLS.get(host, DEFAULT_MAC_POOL)

def next_mac(host:str)->str:
    pool=_pool(host)
    _mac_pos[host]=(_mac_pos[host]+1)%len(pool)
    mac=pool[_mac_pos[host]]
    log.info("HOST %s → MAC %s", host, mac)
    return mac

async def fetch(url:str,*,ttl:int):
    cached=await _cache.get(url)
    if cached: return cached
    try:
        r=await _client.get(url)
    except Exception:
        return b"",599
    await _cache.put(url,r.content,ttl,r.status_code)
    return r.content,r.status_code

SEG_RE=re.compile(r"^(?!#)([^\r\n]+)",re.M)

class Session:
    def __init__(self):
        self.portal_idx=0; self.seg_ok=0; self.last_switch=0.0
        self.base_url="";  self.lock=asyncio.Lock(); self.last_use=time.time()

sessions: Dict[str,Session]=defaultdict(Session)

async def cleanup_sessions():
    while True:
        await asyncio.sleep(15)
        now=time.time()
        idle=[sid for sid,s in sessions.items() if now-s.last_use>SESSION_IDLE_S]
        for sid in idle:
            sessions.pop(sid,None); log.info("Session %s expired",sid)

@app.on_event("startup")
async def _on_start():
    asyncio.create_task(cleanup_sessions())

# ---------------------------------------------------------------------------

def auth_token(host:str, mac:str)->str|None:
    return AUTH_TOKENS.get(mac) if host=="foxx.pure-iptv.net:80" else None

async def obtain_playlist(sid:str,start_idx:int):
    chain=PORTALS[start_idx:]+PORTALS[:start_idx]
    for offs,host in enumerate(chain):
        play_url=f"http://{host}/play/live.php"
        for _ in range(len(_pool(host))):
            mac=next_mac(host)
            params={"mac":mac,"stream":sid,"extension":"m3u8"}
            tok=auth_token(host,mac)
            if tok:
                params["AuthToken"]=tok
            url=f"{play_url}?"+urlencode(params,safe=':')
            log.info("PLAYLIST <= %s",url)
            try:
                r=await _client.get(url)
            except Exception as e:
                log.warning("network err: %s",e); continue
            await _cache.put(str(r.url),r.content,PLAYLIST_TTL,r.status_code)
            if r.status_code==200 and r.content:
                pr=urlparse(str(r.url))
