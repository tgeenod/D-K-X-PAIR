   From __future__ import annotations

import asyncio, base64, gzip, hashlib, hmac, json, random, re, time, uuid
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urljoin, urlparse, quote

import httpx
from bs4 import BeautifulSoup

try:
    import libretube_api as LT
except ImportError:
    LT = None  # type: ignore

# Telegram CDN — always mount when module loads (health/setup/ui need no Telethon).
# Upload/stream need Telethon + env: see GET /tg/setup and GET /tg/ui
tg_router = None  # type: ignore
init_tg_cdn = None  # type: ignore
_TG_CDN_OK = False
try:
    from telegram_cdn_api import router as tg_router, init_tg_cdn
    _TG_CDN_OK = True
except Exception as _tg_err:
    print(f"[StreamHub] telegram_cdn import failed: {_tg_err}")
    tg_router = None  # type: ignore
    init_tg_cdn = None  # type: ignore
    _TG_CDN_OK = False

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, Response, StreamingResponse, PlainTextResponse


# ========== RUNTIME BINDING (internal) ==========
# Multi-factor checksum. Identity material is never stored as plain text.
# Editing decoded identity / hashes / XOR table breaks every route.
def _ci_b(x: int) -> int:
    return x & 0xFF

def _ci_dec(parts, key: int) -> str:
    out = bytearray()
    for i, p in enumerate(parts):
        out.append(_ci_b(p ^ ((key + i * 17) & 0xFF)))
    return out.decode("utf-8")

_CI_P = (41, 3, 29, 250, 241, 193)
_CI_K = 0x5A
_CI_H1 = "6c1b86f4c8f0e0f0e3b8a0c6d2e1f9a0"
_CI_H2 = hashlib.sha256(_ci_dec(_CI_P, _CI_K).encode()).hexdigest()
_CI_H3 = hashlib.md5((_ci_dec(_CI_P, _CI_K) + "|streamhub|v9").encode()).hexdigest()
_CI_H4 = hashlib.sha1((_ci_dec(_CI_P, _CI_K) + "#bind").encode()).hexdigest()
_CI_OK = True

def _ci_name() -> str:
    return _ci_dec(_CI_P, _CI_K)

def _ci_lock_msg() -> dict:
    return {
        "ok": False,
        "error": "API integrity check failed. Restore the original creator binding; without it no endpoint will work.",
        "code": "CI_LOCK",
        "hint": "Do not rename or strip the runtime binding block.",
    }

def _ci_verify() -> bool:
    global _CI_OK
    try:
        n = _ci_name()
        if len(n) != 6:
            _CI_OK = False
            return False
        if hashlib.sha256(n.encode()).hexdigest() != _CI_H2:
            _CI_OK = False
            return False
        if hashlib.md5((n + "|streamhub|v9").encode()).hexdigest() != _CI_H3:
            _CI_OK = False
            return False
        if hashlib.sha1((n + "#bind").encode()).hexdigest() != _CI_H4:
            _CI_OK = False
            return False
        if not (n[0] == "s" and n[-1] == "n" and n[1:4] == "haw"):
            _CI_OK = False
            return False
        if sum(ord(c) for c in n) != 656:
            _CI_OK = False
            return False
        _CI_OK = True
        return True
    except Exception:
        _CI_OK = False
        return False

def _ci_bind_creator():
    if not _ci_verify():
        return "\x00invalid"
    return _ci_name()

_ci_verify()

VERSION = "9.4.0"
CREATOR = _ci_bind_creator()

app = FastAPI(title="StreamHub API", version=VERSION, docs_url=None, redoc_url=None)

@app.middleware("http")
async def _ci_lock_mw(request, call_next):  # CI_LOCK_MW
    if not _ci_verify() or CREATOR != _ci_name() or not _CI_OK:
        from fastapi.responses import JSONResponse
        return JSONResponse(_ci_lock_msg(), status_code=403)
    return await call_next(request)

@app.exception_handler(Exception)
async def unhandled_exception_handler(request, exc):
    from fastapi.responses import JSONResponse
    from fastapi import HTTPException as _H
    if isinstance(exc, _H):
        return JSONResponse(status_code=exc.status_code, content=exc.detail if isinstance(exc.detail, dict) else {"ok": False, "error": str(exc.detail)})
    return JSONResponse(status_code=500, content={"creator": _ci_name() if _ci_verify() else None, "ok": False, "error": f"{type(exc).__name__}: {exc}", "path": str(request.url.path)})

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

if _TG_CDN_OK and tg_router is not None:
    try:
        app.include_router(tg_router)

        @app.on_event("startup")
        async def _startup_tg_cdn():
            try:
                if init_tg_cdn:
                    await init_tg_cdn()
            except Exception as e:
                print(f"[StreamHub] Telegram CDN init deferred: {e}")
    except Exception as e:
        print(f"[StreamHub] Telegram CDN mount failed: {e}")
        _TG_CDN_OK = False

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
MOBILE_UA = "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36"

def ok(data=None, **extra):
    if not _ci_verify() or CREATOR != _ci_name():
        return _ci_lock_msg()
    o = {"creator": CREATOR, "ok": True}
    if data is not None:
        o["data"] = data
    o.update(extra)
    return o

def fail(msg, **extra):
    if not _ci_verify() or CREATOR != _ci_name():
        return _ci_lock_msg()
    o = {"creator": CREATOR, "ok": False, "error": msg}
    o.update(extra)
    return o

def _client(timeout=25.0):
    return httpx.AsyncClient(
        timeout=httpx.Timeout(timeout, connect=10.0),
        follow_redirects=True,
        headers={"User-Agent": UA, "Accept": "*/*", "Accept-Language": "en-US,en;q=0.9"},
        limits=httpx.Limits(max_connections=40, max_keepalive_connections=20),
    )

# ========== MOVIEBOX ==========
# Renewed from mesamirh/MovieBox-Tui (hosts, HMAC, client fingerprint, resource/v2, placeholder recovery)
MB_HOSTS = [
    "https://api6.aoneroom.com", "https://api5.aoneroom.com", "https://api4.aoneroom.com",
    "https://api4sg.aoneroom.com", "https://api3.aoneroom.com", "https://api6sg.aoneroom.com",
    "https://api.inmoviebox.com",
]
MB_SECRET = bytes([0xEF,0xA8,0x91,0x97,0x4E,0xEC,0xD3,0x14,0x8D,0xF6,0x3A,0xA6,0x11,0x60,0x2D,0xEF,0xD1,0x01,0x25,0x9B,0xA5,0x21,0x02,0x2C,0x57,0xAE,0x05,0x66,0xBD,0x8E])
MB_SIGNATURE_BODY_MAX = 102_400
MB_STREAM_REFERER = "https://sportslive.wine"
MB_RETRY_STATUS = (403, 406, 407, 429, 500, 502, 503, 504)
MB_IP_PREFIXES = (
    "103.241", "49.36", "117.195", "106.198", "122.162", "157.32", "182.70", "103.58", "27.60", "59.90",
)
_mb_token = None
_mb_token_exp = 0.0
_mb_host_idx = 0
_mb_device_id = "".join(random.choice("0123456789abcdef") for _ in range(32))
_mb_gaid = str(uuid.uuid4())
_mb_ua = None
_mb_ci = None

def _md5_hex(b: bytes) -> str:
    return hashlib.md5(b).hexdigest()

def _mb_random_ip() -> str:
    p = random.choice(MB_IP_PREFIXES)
    return f"{p}.{random.randint(1,254)}.{random.randint(1,254)}"

def _mb_client_info():
    """Randomized Android fingerprint matching MovieBox-TUI crypto.rs."""
    global _mb_ua, _mb_ci
    if _mb_ua and _mb_ci:
        return _mb_ua, _mb_ci
    android_versions = [
        ("9", "PQ3A.190605.03081104"),
        ("10", "QP1A.191005.007.A3"),
        ("11", "RP1A.200720.011"),
        ("12", "S1B.220414.015"),
        ("13", "TQ2A.230405.003"),
    ]
    redmi_devices = [
        ("23078RKD5C", "Redmi"),
        ("2201117TY", "Redmi"),
        ("2201117TG", "Redmi"),
        ("22101316G", "Redmi"),
        ("21121210G", "Redmi"),
        ("M2012K11AG", "Redmi"),
        ("M2007J20CG", "Redmi"),
    ]
    version_codes = [50020117, 50020118, 50020119, 50020120, 50020121]
    network_types = ["NETWORK_WIFI", "NETWORK_MOBILE"]
    timezones = ["Asia/Kolkata", "Asia/Shanghai", "Asia/Tokyo", "America/New_York", "Europe/London"]

    android = random.choice(android_versions)
    device = random.choice(redmi_devices)
    vc = random.choice(version_codes)
    network = random.choice(network_types)
    timezone = random.choice(timezones)
    gaid = _mb_gaid
    device_id = _mb_device_id

    ua = (
        f"com.community.oneroom/{vc} (Linux; U; Android {android[0]}; en_US; "
        f"{device[0]}; Build/{android[1]}; Cronet/135.0.7012.3)"
    )
    ci = json.dumps({
        "package_name": "com.community.oneroom",
        "version_name": "4.0.01.0813.03",
        "version_code": vc,
        "os": "android",
        "os_version": android[0],
        "install_ch": "ps",
        "device_id": device_id,
        "install_store": "ps",
        "gaid": gaid,
        "brand": device[1],
        "model": device[0],
        "system_language": "en",
        "net": network,
        "region": "US",
        "timezone": timezone,
        "sp_code": "40401",
        "X-Play-Mode": "2",
    }, separators=(",", ":"))
    _mb_ua, _mb_ci = ua, ci
    return ua, ci

def _mb_sign(method, url, body=None):
    ts = int(time.time() * 1000)
    p = urlparse(url)
    params = sorted(parse_qsl(p.query, keep_blank_values=True))
    qs = "&".join(f"{k}={v}" for k, v in params)
    canon = p.path + (f"?{qs}" if qs else "")
    body_b = (body or "").encode()
    # TUI truncates body for signature at 102400 bytes
    body_for_hash = body_b[:MB_SIGNATURE_BODY_MAX] if body_b else b""
    bh = _md5_hex(body_for_hash) if body_b else ""
    bl = str(len(body_b)) if body_b else ""
    accept = ctype = "application/json"
    canonical = f"{method.upper()}\n{accept}\n{ctype}\n{bl}\n{ts}\n{bh}\n{canon}"
    sig = base64.b64encode(hmac.new(MB_SECRET, canonical.encode(), hashlib.md5).digest()).decode()
    rev = str(ts)[::-1]
    ua, ci = _mb_client_info()
    return {
        "Accept": accept,
        "Content-Type": ctype,
        "Connection": "keep-alive",
        "User-Agent": ua,
        "x-client-token": f"{ts},{_md5_hex(rev.encode())}",
        "x-tr-signature": f"{ts}|2|{sig}",
        "x-client-info": ci,
        "x-client-status": "0",
        "x-forwarded-for": _mb_random_ip(),
    }

def _mb_unwrap(payload):
    if isinstance(payload, dict) and isinstance(payload.get("data"), dict):
        return payload["data"]
    return payload if isinstance(payload, dict) else {}

async def _mb_request(method, path, body=None, token=None):
    global _mb_host_idx
    last = "hosts exhausted"
    async with _client(18) as client:
        for i in range(len(MB_HOSTS)):
            base = MB_HOSTS[(_mb_host_idx + i) % len(MB_HOSTS)]
            url = base + path
            headers = _mb_sign(method, url, body)
            if token:
                headers["Authorization"] = f"Bearer {token}"
            try:
                if method.upper() == "GET":
                    r = await client.get(url, headers=headers)
                else:
                    r = await client.post(url, content=body or "", headers=headers)
                if r.status_code in MB_RETRY_STATUS:
                    last = f"{base}->{r.status_code}"
                    continue
                if r.status_code >= 400:
                    last = f"{base}->{r.status_code}:{r.text[:120]}"
                    continue
                _mb_host_idx = (_mb_host_idx + i) % len(MB_HOSTS)
                try:
                    return r.json()
                except Exception:
                    return {"raw": r.text[:2000]}
            except Exception as e:
                last = str(e)
                continue
    raise HTTPException(502, detail=fail("MovieBox upstream failed", detail=last))

async def _mb_session():
    global _mb_token, _mb_token_exp
    if _mb_token and time.time() < _mb_token_exp:
        return _mb_token
    data = await _mb_request("POST", "/wefeed-mobile-bff/user-api/visitor-login", "{}")
    token = _mb_unwrap(data).get("token") or data.get("token")
    if not token:
        raise HTTPException(502, detail=fail("MovieBox login failed", raw=data))
    _mb_token = str(token)
    _mb_token_exp = time.time() + 3500
    return _mb_token



def _dash_from_cookie(sign_cookie):
    """Resolve DASH MPD base from Edge-Cache-Cookie / urlprefix / CloudFront-Policy."""
    if not sign_cookie:
        return None
    m = re.search(r"urlprefix=([A-Za-z0-9+/=_\-]+)", sign_cookie)
    if m:
        raw = m.group(1).replace("-", "+").replace("_", "/")
        pad = raw + "=" * ((4 - len(raw) % 4) % 4)
        try:
            base = base64.b64decode(pad).decode("utf-8", "ignore")
        except Exception:
            base = ""
        if base.startswith("http") and "/dash/" in base:
            base = base.rstrip("*").rstrip("/")
            cookie = sign_cookie if sign_cookie.startswith("Edge-Cache-Cookie=") else f"Edge-Cache-Cookie={sign_cookie}"
            return {
                "url": base + "/index.mpd",
                "format": "DASH",
                "kind": "dash",
                "cookie": cookie,
                "base": base,
                "note": "Send Cookie header when playing",
            }
    m2 = re.search(r"CloudFront-Policy=([^;]+)", sign_cookie)
    if m2:
        pol = m2.group(1).replace("-", "+").replace("_", "/")
        pad = pol + "=" * ((4 - len(pol) % 4) % 4)
        try:
            decoded = base64.b64decode(pad).decode("utf-8", "ignore")
            um = re.search(r'https?://[^"*\s]+/dash/[^"*\s]+', decoded)
            if um:
                base = um.group(0).rstrip("*").rstrip("/")
                cookie = sign_cookie if ("Edge-Cache-Cookie=" in sign_cookie or "CloudFront-" in sign_cookie) else f"Edge-Cache-Cookie={sign_cookie}"
                return {
                    "url": base + "/index.mpd",
                    "format": "DASH",
                    "kind": "dash",
                    "cookie": cookie,
                    "base": base,
                    "note": "Send Cookie header when playing",
                }
        except Exception:
            pass
    return None


def _mb_dash_token(base: str, cookie: str) -> str:
    payload = json.dumps({"b": (base or "").rstrip("/"), "c": cookie or ""}, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(payload).decode().rstrip("=")


def _mb_proxy_mpd_url(base: str, cookie: str, origin: str = "") -> str:
    tok = _mb_dash_token(base, cookie)
    rel = f"/px/{tok}/index.mpd"
    if origin:
        return origin.rstrip("/") + rel
    return rel


def _mb_proxy_seg_url(base: str, cookie: str, segment: str, origin: str = "") -> str:
    tok = _mb_dash_token(base, cookie)
    base = (base or "").rstrip("/")
    u = (segment or "").strip()
    if not u:
        return ""
    if base and u.startswith(base):
        rel = u[len(base):].lstrip("/")
    elif u.startswith("http"):
        try:
            pu = urlparse(u)
            rel = pu.path.lstrip("/")
        except Exception:
            rel = u.split("/")[-1]
    else:
        rel = u.lstrip("/")
    path = f"/px/{tok}/{rel}"
    if origin:
        return origin.rstrip("/") + path
    return path


def _xml_local(tag: str) -> str:
    if not tag:
        return ""
    return tag.split("}")[-1] if "}" in tag else tag


def _rewrite_mpd_for_proxy(mpd_xml: str, base: str, cookie: str, public_base: str = "") -> str:
    base = (base or "").rstrip("/")
    if not base or not mpd_xml:
        return mpd_xml
    tok = _mb_dash_token(base, cookie)
    if public_base:
        bu = public_base.rstrip("/") + "/px/" + tok + "/"
    else:
        bu = "/px/" + tok + "/"
    text = mpd_xml.replace("\x01", "")
    def _bu(_m):
        return "<BaseURL>" + bu + "</BaseURL>"
    if re.search(r"<BaseURL>[^<]*</BaseURL>", text):
        text = re.sub(r"<BaseURL>[^<]*</BaseURL>", _bu, text, count=1)
    else:
        def _ins(m):
            return m.group(1) + "<BaseURL>" + bu + "</BaseURL>"
        text2, n = re.subn(r"(<(?:[\w.]+:)?Period\b[^>]*>)", _ins, text, count=1)
        if n:
            text = text2
        else:
            text2, n = re.subn(r"(<(?:[\w.]+:)?AdaptationSet\b)", lambda m: "<BaseURL>" + bu + "</BaseURL>" + m.group(1), text, count=1)
            if n:
                text = text2
    return text


def _parse_mpd_reps(mpd_xml: str, base: str, cookie: str, origin: str = "") -> list:
    import xml.etree.ElementTree as ET
    out = []
    try:
        root = ET.fromstring(mpd_xml)
    except Exception:
        return out
    base = (base or "").rstrip("/")
    play = _mb_proxy_mpd_url(base, cookie, origin) if base else None

    def abs_url(u: str) -> str:
        if not u:
            return ""
        if u.startswith("http"):
            return u
        if u.startswith("/"):
            try:
                p = urlparse(base)
                return f"{p.scheme}://{p.netloc}{u}"
            except Exception:
                return (base or "") + u
        return (base or "").rstrip("/") + "/" + u.lstrip("/")

    def proxy_path(u: str) -> str:
        return _mb_proxy_seg_url(base, cookie, u, origin) if u else ""

    for period in root.iter():
        if _xml_local(period.tag) != "Period":
            continue
        for aset in period:
            if _xml_local(aset.tag) != "AdaptationSet":
                continue
            for rep in aset:
                if _xml_local(rep.tag) != "Representation":
                    continue
                rid = rep.attrib.get("id") or ""
                bw = rep.attrib.get("bandwidth") or "0"
                w = rep.attrib.get("width")
                h = rep.attrib.get("height")
                codecs = rep.attrib.get("codecs") or ""
                mime = rep.attrib.get("mimeType") or aset.attrib.get("mimeType") or ""
                base_url = ""
                for child in list(rep) + list(aset):
                    if _xml_local(child.tag) == "BaseURL" and (child.text or "").strip():
                        base_url = abs_url(child.text.strip())
                        break
                media_tmpl = init_tmpl = None
                for child in list(rep) + list(aset):
                    if _xml_local(child.tag) == "SegmentTemplate":
                        media_tmpl = child.attrib.get("media")
                        init_tmpl = child.attrib.get("initialization")
                        break
                quality = f"{h}p" if h else (f"{int(bw)//1000}k" if str(bw).isdigit() else rid or "auto")
                kind = "video" if ("video" in (mime or "").lower() or h) else ("audio" if "audio" in (mime or "").lower() else "stream")
                item = {
                    "id": rid,
                    "quality": quality,
                    "width": int(w) if w and str(w).isdigit() else None,
                    "height": int(h) if h and str(h).isdigit() else None,
                    "bandwidth": int(bw) if bw and str(bw).isdigit() else None,
                    "codecs": codecs,
                    "mime": mime,
                    "kind": kind,
                    "base_url": base_url or None,
                    "play_url": play,
                    "cdn_base": base,
                }
                if init_tmpl:
                    init_u = abs_url(init_tmpl.replace("$RepresentationID$", rid).replace("$Bandwidth$", str(bw or "")))
                    item["init_segment_cdn"] = init_u
                    item["init_play"] = proxy_path(init_u)
                if media_tmpl:
                    item["media_template"] = media_tmpl
                out.append(item)
    seen = set()
    uniq = []
    for x in out:
        k = (x.get("id"), x.get("bandwidth"), x.get("height"))
        if k in seen:
            continue
        seen.add(k)
        uniq.append(x)
    uniq.sort(key=lambda x: (0 if x.get("kind") == "video" else 1, -(x.get("height") or 0), -(x.get("bandwidth") or 0)))
    return uniq


async def _mb_fetch_mpd(base: str, cookie: str) -> str:
    mpd_url = (base or "").rstrip("/") + "/index.mpd"
    headers = {
        "User-Agent": _mb_client_info()[0],
        "Accept": "application/dash+xml,application/xml,*/*",
        "Referer": MB_STREAM_REFERER,
    }
    if cookie:
        headers["Cookie"] = cookie if (cookie.startswith("Edge-Cache-Cookie=") or "CloudFront-" in cookie) else f"Edge-Cache-Cookie={cookie}"
    async with _client(20) as client:
        r = await client.get(mpd_url, headers=headers)
        r.raise_for_status()
        return r.text


def _mb_is_deprecation_notice_url(url: str) -> bool:
    """Match MovieBox-TUI adapt::is_deprecation_notice_url — skip placeholder clips."""
    if not url:
        return True
    lower = url.lower()
    return (
        "1c7de0bd3393702d9191801f15f88f8d" in lower
        or "9a0461bc39da389663bf3dbb17091d3f" in lower
        or "b164fbfb4347792950bdfbfb563d39d9" in lower
        or "/notice.mp4" in lower
        or "upgrade" in lower and "notice" in lower
        or ("macdn.aoneroom.com" in lower and "/other/" in lower)
        or ("macdn.aoneroom.com" in lower and "/notice" in lower)
    )

def _mb_streams(payload, include_placeholders: bool = False):
    """Parse play-info streams. Placeholders excluded unless include_placeholders=True."""
    streams = []
    data = _mb_unwrap(payload)
    for s in (data.get("streams") or data.get("list") or []):
        if not isinstance(s, dict):
            continue
        url = s.get("url") or s.get("playUrl") or s.get("streamUrl") or ""
        cookie = s.get("signCookie") or s.get("cookie") or ""
        dash = _dash_from_cookie(cookie)
        if dash:
            dash["id"] = s.get("id")
            dash["quality"] = s.get("resolutions") or s.get("quality")
            dash["codec"] = s.get("codecName") or s.get("codec") or "h265"
            streams.append(dash)
        is_ph = _mb_is_deprecation_notice_url(url)
        if url and not is_ph:
            streams.append({
                "id": s.get("id"),
                "url": url,
                "quality": s.get("resolutions") or s.get("quality"),
                "codec": s.get("codecName") or s.get("codec"),
                "format": s.get("format") or "MP4",
                "size": s.get("size"),
                "duration": s.get("duration"),
                "cookie": cookie or None,
                "kind": "mp4",
                "source": "play-info",
            })
        elif url and is_ph and include_placeholders:
            streams.append({
                "id": s.get("id"),
                "url": url,
                "quality": s.get("resolutions") or s.get("quality"),
                "codec": s.get("codecName") or s.get("codec"),
                "format": "MP4",
                "size": s.get("size"),
                "kind": "mp4",
                "placeholder": True,
                "source": "play-info",
                "note": "Placeholder/deprecation notice — not a real movie file",
            })
    return streams


def _mb_streams_from_detectors(detail_payload) -> list:
    """Real MP4s from subject get → resourceDetectors (MovieBox-TUI detector path)."""
    try:
        data = _mb_unwrap(detail_payload)
    except Exception:
        return []
    if not isinstance(data, dict):
        return []
    title = data.get("title") or data.get("subjectTitle") or ""
    out = []
    seen = set()
    detectors = data.get("resourceDetectors") or []
    if not isinstance(detectors, list):
        return []
    for det in detectors:
        if not isinstance(det, dict):
            continue
        res_list = det.get("resolutionList") or []
        if isinstance(res_list, list) and res_list:
            for item in res_list:
                if not isinstance(item, dict):
                    continue
                link = item.get("resourceLink") or item.get("url") or item.get("downloadUrl") or ""
                if not link or not str(link).startswith("http"):
                    continue
                if _mb_is_deprecation_notice_url(str(link)):
                    continue
                # Drop non-CDN junk (fzmovies html pages etc.)
                _host = (urlparse(str(link)).hostname or "").lower()
                if not any(h in _host for h in (
                    "hakunaymatata.com", "aoneroom.com", "cloudfront.net",
                    "googleusercontent.com", "r2.cloudflarestorage.com",
                )) and not re.search(r"\.(mp4|mkv|m3u8)(\?|$)", str(link), re.I):
                    continue
                key = str(link).split("?")[0]
                if key in seen:
                    continue
                seen.add(key)
                size = item.get("size") or item.get("firstSize")
                try:
                    size = int(size) if size is not None else None
                except Exception:
                    size = None
                out.append({
                    "id": item.get("resourceId") or det.get("resourceId"),
                    "url": str(link),
                    "play_url": str(link),
                    "quality": item.get("resolution") or item.get("title") or det.get("source"),
                    "codec": item.get("codecName") or det.get("codecName") or "h265",
                    "format": "MP4",
                    "size": size,
                    "kind": "mp4",
                    "source": "resourceDetectors",
                    "uploadBy": item.get("uploadBy") or det.get("uploadBy"),
                    "se": item.get("se"),
                    "ep": item.get("ep") or item.get("episode"),
                    "title": item.get("title") or title,
                    "cookie_required_on_client": False,
                    "placeholder": False,
                })
            continue
        link = det.get("downloadUrl") or det.get("resourceLink") or ""
        if link and str(link).startswith("http") and not _mb_is_deprecation_notice_url(str(link)):
            key = str(link).split("?")[0]
            if key not in seen:
                seen.add(key)
                size = det.get("firstSize") or det.get("size")
                try:
                    size = int(size) if size is not None else None
                except Exception:
                    size = None
                out.append({
                    "id": det.get("resourceId"),
                    "url": str(link),
                    "play_url": str(link),
                    "quality": det.get("source") or "default",
                    "codec": det.get("codecName") or "h265",
                    "format": "MP4",
                    "size": size,
                    "kind": "mp4",
                    "source": "resourceDetectors",
                    "uploadBy": det.get("uploadBy"),
                    "title": title,
                    "cookie_required_on_client": False,
                    "placeholder": False,
                })
    return out

async def _mb_safe_get(path: str, token: str):
    """Never raises — returns (data_or_none, error_str_or_none)."""
    try:
        data = await _mb_request("GET", path, token=token)
        return data, None
    except HTTPException as e:
        return None, str(getattr(e, "detail", e))[:200]
    except Exception as e:
        return None, str(e)[:200]

async def _mb_collect_playable(subject_id: str, se: Optional[int] = None, ep: Optional[int] = None) -> dict:
    """Aggregate real playable streams: detectors first, then play-info DASH/mp4, then resource recovery."""
    errors = []
    try:
        tok = await _mb_session()
    except Exception as e:
        return {
            "subject_id": subject_id, "title": None, "season": se, "episode": ep,
            "dash": [], "mp4": [], "streams": [], "count": 0,
            "has_real_streams": False, "errors": [f"login:{e}"],
        }

    if se is not None and ep is not None:
        play_path = f"/wefeed-mobile-bff/subject-api/play-info/v2?subjectId={subject_id}&se={se}&ep={ep}"
        res_path = _mb_episode_resource_path(subject_id, int(se), int(ep))
    else:
        play_path = f"/wefeed-mobile-bff/subject-api/play-info/v2?subjectId={subject_id}"
        res_path = f"/wefeed-mobile-bff/subject-api/resource?subjectId={subject_id}&page=1&perPage=20"
    detail_path = f"/wefeed-mobile-bff/subject-api/get?subjectId={subject_id}"

    # Sequential is more reliable on serverless (avoid connection pool races)
    play_data, e1 = await _mb_safe_get(play_path, tok)
    if e1:
        errors.append(f"play-info:{e1}")
    detail_data, e2 = await _mb_safe_get(detail_path, tok)
    if e2:
        errors.append(f"detail:{e2}")
    res_data, e3 = await _mb_safe_get(res_path, tok)
    if e3:
        errors.append(f"resource:{e3}")

    inner = _mb_unwrap(play_data) if play_data else {}
    detail_inner = _mb_unwrap(detail_data) if detail_data else {}
    title = (inner.get("title") if isinstance(inner, dict) else None) or (
        detail_inner.get("title") if isinstance(detail_inner, dict) else None
    )

    dash, mp4 = [], []
    seen = set()

    def _add_mp4(item: dict):
        if not isinstance(item, dict):
            return
        u = item.get("url") or item.get("play_url") or ""
        if not u or _mb_is_deprecation_notice_url(str(u)):
            return
        key = str(u).split("?")[0]
        if key in seen:
            return
        seen.add(key)
        row = dict(item)
        row["url"] = str(u)
        row.setdefault("play_url", str(u))
        row.setdefault("kind", "mp4")
        row["placeholder"] = False
        row["cookie_required_on_client"] = False
        mp4.append(row)

    # 1) resourceDetectors — primary real files
    if detail_data:
        for s in _mb_streams_from_detectors(detail_data):
            try:
                if se is not None and s.get("se") not in (None, se, 0, "0"):
                    continue
                if ep is not None and s.get("ep") not in (None, ep, 0, "0"):
                    continue
            except Exception:
                pass
            _add_mp4(s)

    # 2) play-info DASH + clean mp4
    if play_data:
        try:
            for s in _mb_streams(play_data, include_placeholders=False):
                if not isinstance(s, dict):
                    continue
                if s.get("kind") == "dash" and s.get("base"):
                    s2 = dict(s)
                    try:
                        s2["play_url"] = _mb_proxy_mpd_url(s2["base"], s2.get("cookie") or "", "")
                        s2["px_path"] = s2["play_url"]
                    except Exception:
                        s2["play_url"] = (s2.get("url") or "")
                    s2["cookie_required_on_client"] = False
                    s2["kind"] = "dash"
                    dash.append(s2)
                else:
                    _add_mp4(s)
        except Exception as e:
            errors.append(f"streams:{e}")

    # 3) resource list + position recovery
    if res_data:
        try:
            res_inner = _mb_unwrap(res_data)
            for item in (res_inner.get("list") or []) if isinstance(res_inner, dict) else []:
                if not isinstance(item, dict):
                    continue
                link = item.get("resourceLink") or item.get("url") or ""
                rid = item.get("resourceId") or item.get("id")
                if link and not _mb_is_deprecation_notice_url(str(link)):
                    _add_mp4({
                        "id": rid, "url": link, "size": item.get("size"),
                        "quality": item.get("resolution"), "codec": item.get("codecName"),
                        "source": "resource", "se": item.get("se"), "ep": item.get("ep"),
                    })
                    continue
                if rid and link and _mb_is_deprecation_notice_url(str(link)):
                    try:
                        pos_path = _mb_resource_position_path(subject_id, str(rid), str(link))
                        pos, pe = await _mb_safe_get(pos_path, tok)
                        if not pos:
                            continue
                        for cand in (_mb_unwrap(pos).get("list") or []):
                            if not isinstance(cand, dict):
                                continue
                            clink = cand.get("resourceLink") or cand.get("url") or ""
                            if clink and not _mb_is_deprecation_notice_url(str(clink)):
                                _add_mp4({
                                    "id": rid, "url": clink,
                                    "size": cand.get("size") or item.get("size"),
                                    "quality": cand.get("resolution") or item.get("resolution"),
                                    "codec": cand.get("codecName") or item.get("codecName"),
                                    "source": "resource-position", "recovered": True,
                                })
                                break
                    except Exception:
                        pass
        except Exception as e:
            errors.append(f"resource-parse:{e}")

    def _sz(x):
        try:
            return int(x.get("size") or 0)
        except Exception:
            return 0
    mp4.sort(key=_sz, reverse=True)

    return {
        "subject_id": subject_id,
        "title": title,
        "season": se,
        "episode": ep,
        "dash": dash,
        "mp4": mp4,
        "streams": list(dash) + list(mp4),
        "count": len(dash) + len(mp4),
        "displayResolutions": inner.get("displayResolutions") if isinstance(inner, dict) else None,
        "has_real_streams": bool(dash or mp4),
        "errors": errors or None,
    }

def _mb_items_from_search(inner):
    items = []
    for block in inner.get("results") or []:
        for s in block.get("subjects") or []:
            cover = s.get("cover")
            items.append({
                "subjectId": s.get("subjectId") or s.get("id"),
                "title": s.get("title"),
                "type": s.get("subjectType"),
                "year": (s.get("releaseDate") or "")[:4],
                "genre": s.get("genre"),
                "cover": cover.get("url") if isinstance(cover, dict) else cover,
                "imdb": s.get("imdbRating") or s.get("rating"),
            })
    return items

def _mb_episode_resource_path(subject_id: str, se: int, ep: int) -> str:
    """TUI episode-scoped resource/v2 path."""
    return (
        f"/wefeed-mobile-bff/subject-api/resource/v2?subjectId={subject_id}"
        f"&page=1&perPage=20&all=0&startPosition=1&endPosition=1&pagerMode=2"
        f"&resolution=0&se={se}&epFrom={ep}&epTo={ep}&isVip=true"
    )

def _mb_resource_position_path(subject_id: str, resource_id: str, failed_url: str) -> str:
    from urllib.parse import urlencode
    q = urlencode({
        "subjectId": subject_id,
        "resourceId": resource_id,
        "failUrl": failed_url,
        "failCode": "404",
        "resourceNum": "0",
        "isVip": "true",
    })
    return f"/wefeed-mobile-bff/subject-api/resource-position/v2?{q}"

