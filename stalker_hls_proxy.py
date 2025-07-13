# stalker_hls_proxy.py – лёгкая сборка (memory‑friendly) + AuthToken‑портал, health‑check и /playlistN.m3u8
# ---------------------------------------------------------------------------
# v9  (07 июл 2025)
#   • Исправлены SyntaxError’ы (точка и скобка).
#   • Добавлен корневой «/» handler для health‑check.
#   • Добавлены маршруты /playlistN.m3u8 (1‑5).
#   • 204 No Content считается ошибкой (BAD_CODES).
# ---------------------------------------------------------------------------

from __future__ import annotations
import asyncio, httpx, logging, re, sys, time
from collections import OrderedDict, defaultdict
from typing import Dict, List, Tuple
from urllib.parse import quote, urlencode, unquote, urljoin, urlparse, urlunparse

from fastapi import FastAPI, Path, Response, Query, HTTPException
from starlette.responses import PlainTextResponse, JSONResponse

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------
PORTALS: List[str] = [
    "ledir.thund.re",
    "stalker.ugoiptv.com:80",
    "93.119.105.61:80",
    "clientsportals.tv:2095",    # ← новый портал (idx 3)
    "foxx.pure-iptv.net:80",
]

MAC_POOLS: Dict[str, List[str]] = {
    "ledir.thund.re": [
        "00:1A:79:00:0A:2C", "00:1A:79:1A:04:B7", "00:1A:79:C5:94:26",
        "00:1A:79:79:6E:FF", "00:1A:79:00:37:10", "00:1A:79:1B:F7:B7",
        "00:1A:79:02:13:52", "00:1A:79:B9:81:75", "00:1A:79:01:64:74",
        "00:1A:79:7B:1D:45", "00:1A:79:6E:82:2C",
    ],
    "stalker.ugoiptv.com:80": [
        "00:1A:79:B7:B4:EB", "00:1A:79:71:F3:B0", "00:1A:79:76:2D:D2",
        "00:1A:79:C2:7A:0F", "00:1A:79:BF:90:B0", "00:1A:79:6F:1F:CB",
        "00:1A:79:97:BA:47", "00:1A:79:BE:BF:B5", "00:1A:79:FF:FF:F4",
        "00:1A:79:32:53:16", "00:1A:79:79:F2:42", "00:1A:79:00:1C:5B",
        "00:1A:79:00:18:51", "00:1A:79:B1:66:BD", "00:1A:79:00:11:DE",
        "00:1A:79:42:DA:30", "00:1A:79:31:61:31", "00:1A:79:B3:91:AA",
        "00:1A:79:B6:5F:F0", "00:1A:79:E6:F9:FC", "00:1A:79:C1:1B:1A",
        "00:1A:79:C2:7A:0F", "00:1A:79:BF:90:B0", "00:1A:79:7E:19:2B",
        "00:1A:79:32:C5:93", "00:1A:79:E8:63:0C", "00:1A:79:7E:A9:DC",
        "00:1A:79:13:2C:FD", 
    ],
    "93.119.105.61:80": [
        "00:1A:79:4D:F6:60", "00:1A:79:13:8F:5A", "00:1A:79:00:1F:2B",
        "00:1A:79:B0:64:C2", "00:1A:79:00:40:EF", "00:1A:79:00:27:C5",
        "00:1A:79:82:05:98", "00:1A:79:72:BB:CF", "00:1A:79:79:4C:E4",
        "00:1A:79:00:27:C4", "00:1A:79:4D:6F:C6", "00:1A:79:B5:B1:C2",
        "00:1A:79:C2:7E:5F", "00:1A:79:B5:B6:D5", "00:1A:79:80:5F:4C",
        "00:1A:79:01:B6:C5", "00:1A:79:B0:64:C2", "00:1A:79:00:28:B5",
        "00:1A:79:65:ED:E2", "00:1A:79:B5:B1:C2",     
    ],
    "clientsportals.tv:2095": [
        "00:1A:79:CC:3E:EE", "00:1A:79:BF:C8:FC", "00:1A:79:C8:64:66",
        "00:1A:79:BF:C8:FD", "00:1A:79:B9:E6:73", "00:1A:79:B6:DF:D1",
        "00:1A:79:52:36:AE", "00:1A:79:3C:A7:74", "00:1A:79:4D:EF:D0",
        "00:1A:79:57:66:9E", "00:1A:79:3A:20:9C", "00:1A:79:4D:DD:33",
    ],
    "foxx.pure-iptv.net:80": [
        "00:1A:79:AF:01:C7", "00:1A:79:22:20:42", "00:1A:79:C1:92:57",
        "00:1A:79:BE:55:F2", "00:1A:79:6A:3C:19", "00:1A:79:AC:76:38"
    ],
}

# foxx.pure‑iptv.net: постоянные AuthToken‑ы (по MAC)
TOKEN_HOSTS = {"foxx.pure-iptv.net:80"}

AUTH_TOKENS: Dict[str, str] = {
    "00:1A:79:AF:01:C7": "AC38FF7569DB3E0D41A548EDC5367D23&sn2=",
    "00:1A:79:AC:76:38": "99E271197A32250B0F8DCAA0E9E3A4EA&sn2=",
    "00:1A:79:6A:3C:19": "FCB9D1D3070185FAD9DD9A707ADC160B&sn2=",
    "00:1A:79:C1:92:57": "9727A2E9CC67AA6E67A2A8D25C29EFA5&sn2=",
    "00:1A:79:BE:55:F2": "6BC5B0C9FEA2C54A71704A6D5E528668&sn2=",
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
class LRU(OrderedDict):
    def __init__(self):
        super().__init__(); self.max_k=MAX_CACHE_KEYS; self.max_b=MAX_CACHE_BYTES
        self.now_b=0; self.lock=asyncio.Lock()
    async def get(self,k):
        async with self.lock:
            rec=self.pop(k,None)
            if not rec: return None
            body,exp,st,sz=rec
            if exp<time.time():
                self.now_b-=sz; return None
            self[k]=(body,exp,st,sz)
            return body,st
    async def put(self,k,b,ttl,st):
        if ttl<=0: return
        async with self.lock:
            old=self.pop(k,None)
            if old: self.now_b-=old[3]
            sz=len(b)
            self[k]=(b,time.time()+ttl,st,sz)
            self.now_b+=sz
            while self.now_b>self.max_b or len(self)>self.max_k:
                _,(_,_,_,s)=self.popitem(last=False); self.now_b-=s
_cache=LRU()

_mac_pos: defaultdict[str,int]=defaultdict(lambda:-1)

def _pool(host:str)->List[str]:
    return MAC_POOLS.get(host, DEFAULT_MAC_POOL) if host!="foxx.pure-iptv.net:80" else list(AUTH_TOKENS)

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
        for sid in [sid for sid,s in sessions.items() if now-s.last_use>SESSION_IDLE_S]:
            sessions.pop(sid,None); log.info("Session %s expired",sid)

@app.on_event("startup")
async def _on_start():
    asyncio.create_task(cleanup_sessions())

# ---------------------------------------------------------------------------

def auth_token(host:str, mac:str) -> str | None:
    return AUTH_TOKENS.get(mac) if host in TOKEN_HOSTS else None

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
                pr=urlparse(str(r.url))._replace(query="",fragment="")
                base=(urlunparse(pr) if str(r.url).endswith('/') else urlunparse(pr).rsplit('/',1)[0]+'/')
                idx=(start_idx+offs)%len(PORTALS)
                log.info("PLAYLIST OK – host=%s idx=%s",host,idx)
                return base,r.content,idx
            if r.status_code in BAD_CODES:
                log.warning("MAC %s → HTTP %s (skip)",mac,r.status_code); continue
            log.warning("MAC %s → unexpected HTTP %s",mac,r.status_code)
    raise httpx.HTTPStatusError("No working MAC",request=None,response=None)

# ---------------------------------------------------------------------------

def normalise(seg:str)->str:
    seg=unquote(seg.strip())
    if seg.startswith("%3A//"):
        seg="http"+seg[2:]
    if seg.startswith("://"):
        seg="http"+seg
    if "//" in seg and not seg.startswith(("http://","https://","/")):
        seg="http://"+seg.split("//",1)[-1]
    return seg

def rewrite_m3u8(text:str,*,base:str)->str:
    def repl(m:re.Match):
        seg=normalise(m.group(1))
        full=seg if seg.startswith(("http://","https://")) else urljoin(base,seg)
        u=urlparse(full)
        return f"/segment/{u.scheme}/{u.netloc}{u.path}"
    return SEG_RE.sub(repl,text)

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/")
async def root():
    return JSONResponse({"status":"ok","portals":len(PORTALS)})

# numbered entrypoints /playlist1.m3u8 … /playlist5.m3u8
for n in range(1,len(PORTALS)+1):
    path=f"/playlist{n}.m3u8"
    async def _handler(stream_id:int=Query(...),n=n):
        return PlainTextResponse(status_code=307,headers={"Location":f"/stream/{n-1}/{stream_id}/index.m3u8"})
    app.get(path)(_handler)  # type: ignore

@app.get("/playlist.m3u8")
async def entry_default(stream_id:int):
    return PlainTextResponse(status_code=307,headers={"Location":f"/stream/0/{stream_id}/index.m3u8"})

@app.get("/stream/{portal_idx}/{sid}/index.m3u8")
async def playlist(portal_idx:int,sid:str):
    sess=sessions[sid]
    sess.portal_idx=portal_idx%len(PORTALS)
    sess.seg_ok=0; sess.last_switch=time.time(); sess.last_use=time.time()
    try:
        base,raw,sess.portal_idx=await obtain_playlist(sid,sess.portal_idx)
    except httpx.HTTPStatusError as exc:
        raise HTTPException(502,str(exc))
    sess.base_url=base
    return Response(rewrite_m3u8(raw.decode(errors="ignore"),base=base),media_type="application/vnd.apple.mpegurl")

@app.get("/segment/{proto}/{path:path}")
async def segment(proto:str,path:str):
    url=f"{proto}://{path}"
    body,st=await fetch(url,ttl=SEGMENT_TTL)
    maybe_sid=path.split('/')[-1].split('_')[0]
    sess=sessions.get(maybe_sid)
    if sess:
        sess.last_use=time.time()
        ok=200<=st<300
        sess.seg_ok=sess.seg_ok+1 if ok else SEG_OK_LIMIT
        if sess.seg_ok>=SEG_OK_LIMIT and time.time()-sess.last_switch>MIN_SWITCH_SEC:
            async with sess.lock:
                if sess.seg_ok>=SEG_OK_LIMIT and time.time()-sess.last_switch>MIN_SWITCH_SEC:
                    log.info("=== switching playlist (sid=%s) after %s segments ===",maybe_sid,sess.seg_ok)
                    sess.seg_ok=0; sess.last_switch=time.time()
                    try:
                        await obtain_playlist(maybe_sid,sess.portal_idx)
                    except Exception as e:
                        log.warning("reswitch failed: %s",e)
    return Response(body,media_type="video/MP2T",status_code=st)

# ---------------------------------------------------------------------------
if __name__=="__main__":
    import uvicorn
    port=int(sys.argv[1]) if len(sys.argv)>1 else 8080
    log.info("Proxy ready: %s portals",len(PORTALS))
    uvicorn.run("stalker_hls_proxy:app",host="0.0.0.0",port=port)
