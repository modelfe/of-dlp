#!/usr/bin/env python3
import subprocess, sys, os, pathlib

VENV_DIR = pathlib.Path(__file__).parent / ".venv"
REQUIRED_PACKAGES = ["playwright", "pywidevine"]

def setup_venv():
    if not VENV_DIR.is_dir():
        print("Setting up virtual environment...")
        subprocess.check_call([sys.executable, "-m", "venv", str(VENV_DIR)])
        # Choose the right bin/Scripts folder
        if os.name == "nt":
            bin_dir = VENV_DIR / "Scripts"
        else:
            bin_dir = VENV_DIR / "bin"
        pip = str(bin_dir / "pip")
        subprocess.check_call([pip, "install", *REQUIRED_PACKAGES])

if sys.prefix != str(VENV_DIR):
    setup_venv()
    if os.name == "nt":
        python = str(VENV_DIR / "Scripts" / "python.exe")
    else:
        python = str(VENV_DIR / "bin" / "python")
    result = subprocess.call([python, __file__, *sys.argv[1:]])
    sys.exit(result)

import asyncio
import base64
import binascii
import re
import subprocess
import shutil
import time
import xml.etree.ElementTree as ET
import struct
from pathlib import Path
from urllib.parse import urljoin, urlparse
from uuid import UUID

from playwright.async_api import async_playwright
from pywidevine import Device, DeviceTypes, Cdm, PSSH
from pywidevine.exceptions import InvalidContext, InvalidLicenseMessage, SignatureMismatch
from pywidevine.license_protocol_pb2 import SignedMessage

BROWSER_EXECUTABLE = None
# Tried in order when BROWSER_EXECUTABLE is None.
BROWSER_CHANNEL_PREFERENCE = ["chrome", "msedge", "chrome-beta", "chrome-dev", "chrome-canary"]

# -------------------------------------------------------------------
# ffmpeg configuration
# -------------------------------------------------------------------
FFMPEG_EXECUTABLE = None

def resolve_ffmpeg(script_dir):
    if FFMPEG_EXECUTABLE:
        p = Path(FFMPEG_EXECUTABLE)
        if p.is_file():
            return str(p.resolve())
        print(f"FFMPEG_EXECUTABLE is set but not found: {FFMPEG_EXECUTABLE}")
        return None

    found = shutil.which("ffmpeg")
    if found:
        return str(Path(found).resolve())

    exe_name = "ffmpeg.exe" if os.name == "nt" else "ffmpeg"
    for candidate in (script_dir / exe_name,
                      script_dir / "bin" / exe_name,
                      script_dir / "ffmpeg" / exe_name,
                      script_dir / "ffmpeg" / "bin" / exe_name):
        if candidate.is_file():
            return str(candidate.resolve())

    return None

def print_ffmpeg_help():
    print("-" * 60)
    print("ffmpeg not found.")
    if os.name == "nt":
        print("  - Put ffmpeg.exe next to this script, or")
        print("  - Install it:  winget install Gyan.FFmpeg")
        print("  - Or set FFMPEG_EXECUTABLE at the top of this script.")
    else:
        print("  - sudo apt install ffmpeg   /   sudo dnf install ffmpeg")
        print("  - Or set FFMPEG_EXECUTABLE at the top of this script.")
    print("-" * 60)

# -------------------------------------------------------------------
# Browser configuration
# -------------------------------------------------------------------
def resolve_browser(p):
    if BROWSER_EXECUTABLE:
        path = Path(BROWSER_EXECUTABLE)
        if not path.is_file():
            raise RuntimeError(f"BROWSER_EXECUTABLE not found: {BROWSER_EXECUTABLE}")
        print(f"Using browser: {BROWSER_EXECUTABLE}")
        return {"executable_path": str(path)}

    _channel_bins = {
        "chrome":        ["google-chrome", "google-chrome-stable", "chrome"],
        "msedge":        ["microsoft-edge", "microsoft-edge-stable", "msedge"],
        "chrome-beta":   ["google-chrome-beta", "chrome-beta"],
        "chrome-dev":    ["google-chrome-unstable", "chrome-unstable"],
        "chrome-canary": ["google-chrome-canary", "chrome-canary"],
    }

    for channel in BROWSER_CHANNEL_PREFERENCE:
        bins = _channel_bins.get(channel, [])
        found = any(shutil.which(b) for b in bins)
        if found:
            print(f"Using browser channel: {channel}")
            return {"channel": channel}

    for channel in BROWSER_CHANNEL_PREFERENCE:
        print(f"Trying browser channel: {channel} ...")
        return {"channel": channel}

    raise RuntimeError(
        "No supported browser found. Install Google Chrome, or set "
        "BROWSER_EXECUTABLE at the top of the script to your browser's path."
    )

# -------------------------------------------------------------------
# Constants + small helpers
# -------------------------------------------------------------------
WIDEVINE_SYSTEM_ID = UUID("edef8ba9-79d6-4ace-a3c8-27dcd51d21ed")
CENC_DEFAULT_KID = "{urn:mpeg:cenc:2013}default_KID"
HOP_BY_HOP_HEADERS = {
    "content-length", "transfer-encoding", "connection", "keep-alive",
    "host", "accept-encoding", "upgrade", "te", "trailer", "proxy-connection",
}
CONTAINER_BOX_TYPES = {
    b"moov", b"trak", b"mdia", b"minf", b"stbl", b"dinf", b"edts",
    b"mvex", b"moof", b"traf", b"mfra", b"udta", b"meta", b"sinf",
    b"schi", b"ipro", b"skip",
}

def local(tag):
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else tag

def iter_children(elem):
    return list(elem)

def first_child(elem, name):
    for child in elem:
        if local(child.tag) == name:
            return child
    return None

def iter_desc(elem, name):
    for child in elem.iter():
        if local(child.tag) == name:
            yield child

def build_parent_map(root):
    return {child: parent for parent in root.iter() for child in parent}

def strip_cdata(value):
    if value is None:
        return None
    value = value.strip()
    m = re.fullmatch(r"<!\[CDATA\[(.*)\]\]>", value, flags=re.DOTALL)
    if m:
        return m.group(1).strip()
    return value

def decode_pssh_b64(raw):
    """Decode a (possibly CDATA-wrapped, whitespace-padded) base64 PSSH string."""
    raw = strip_cdata(raw)
    if not raw:
        return None
    raw = re.sub(r"\s+", "", raw)
    candidates = [raw]
    if len(raw) % 4:
        candidates.append(raw + "=" * (-len(raw) % 4))
    for cand in candidates:
        try:
            data = base64.b64decode(cand, validate=False)
            if data:
                return data
        except (binascii.Error, ValueError):
            continue
    return None

def normalize_kid(value):
    if value is None:
        return None
    if isinstance(value, UUID):
        return value
    if isinstance(value, bytes):
        if len(value) == 16:
            return UUID(bytes=value)
        try:
            return UUID(hex=value.decode().strip())
        except (ValueError, UnicodeDecodeError):
            return None
    if isinstance(value, str):
        s = value.strip().replace("-", "")
        try:
            if len(s) == 32:
                return UUID(hex=s)
            return UUID(value)
        except ValueError:
            return None
    return None

# -------------------------------------------------------------------
# MP4 box parsing (for locating PSSH inside init segments)
# -------------------------------------------------------------------
def iter_boxes(data):
    n = len(data)
    offset = 0
    while offset + 8 <= n:
        size = struct.unpack_from(">I", data, offset)[0]
        typ = bytes(data[offset + 4:offset + 8])
        header = 8
        if size == 1:
            if offset + 16 > n:
                break
            size = struct.unpack_from(">Q", data, offset + 8)[0]
            header = 16
        elif size == 0:
            size = n - offset
        if size < header or offset + size > n:
            break
        yield typ, offset, size, header
        offset += size

def _walk_boxes(buf, depth, found):
    if depth > 12:
        return
    for typ, off, size, header in iter_boxes(buf):
        if typ == b"pssh":
            found.append(bytes(buf[off:off + size]))
        elif typ in CONTAINER_BOX_TYPES:
            _walk_boxes(buf[off + header:off + size], depth + 1, found)

def find_pssh_boxes(data):
    found = []
    _walk_boxes(memoryview(data), 0, found)
    return found

def find_widevine_pssh_boxes(data):
    result = []
    for box in find_pssh_boxes(data):
        if len(box) >= 28:
            try:
                if UUID(bytes=bytes(box[12:28])) == WIDEVINE_SYSTEM_ID:
                    result.append(box)
            except ValueError:
                continue
    return result

# -------------------------------------------------------------------
# Manifest / PSSH extraction
# -------------------------------------------------------------------
def extract_manifest_pssh(root):
    """Widevine <cenc:pssh> inside ContentProtection in the MPD."""
    for cp in iter_desc(root, "ContentProtection"):
        scheme = (cp.get("schemeIdUri") or "").lower()
        if "edef8ba9-79d6-4ace-a3c8-27dcd51d21ed" not in scheme:
            continue
        pssh_el = first_child(cp, "pssh")
        if pssh_el is None:
            continue
        data = decode_pssh_b64(pssh_el.text)
        if data:
            return data
    return None

def extract_playready_pssh(root):
    """Convert a PlayReady mspr:pro / cenc:pssh into a Widevine PSSH box."""
    for cp in iter_desc(root, "ContentProtection"):
        scheme = (cp.get("schemeIdUri") or "").lower()
        if "9a04f079-9840-4286-ab92-e65be0885f95" not in scheme:
            continue
        pssh_el = first_child(cp, "pssh")
        if pssh_el is not None:
            raw = pssh_el.text
        else:
            pro_el = first_child(cp, "pro")
            raw = pro_el.text if pro_el is not None else None
        data = decode_pssh_b64(raw)
        if not data:
            continue
        try:
            pssh = PSSH(data)
            if pssh.system_id == PSSH.SystemId.PlayReady:
                pssh.to_widevine()
                return pssh.dump()
            if pssh.system_id == PSSH.SystemId.Widevine:
                return pssh.dump()
        except Exception as exc:
            print(f"   ⚠ PlayReady PSSH conversion failed: {exc}")
    return None

def pssh_fallback_from_text(text):
    """Last resort: find base64-looking PSSH blobs directly in the MPD text."""
    for match in re.finditer(r"(AAAA[A-Za-z0-9+/=]{20,})", text):
        data = decode_pssh_b64(match.group(1))
        if data and len(data) >= 8:
            return data
    return None

def collect_manifest_kids(root):
    kids = []
    for cp in iter_desc(root, "ContentProtection"):
        val = cp.get(CENC_DEFAULT_KID) or cp.get("default_KID")
        if val:
            kids.append(val)
    for rep in iter_desc(root, "Representation"):
        val = rep.get(CENC_DEFAULT_KID) or rep.get("default_KID")
        if val:
            kids.append(val)
    return kids

def fill_segment_template(template, rep, seg_tpl=None, number=1):
    out = template or ""
    start = 1
    if seg_tpl is not None and seg_tpl.get("startNumber"):
        try:
            start = int(seg_tpl.get("startNumber"))
        except ValueError:
            start = 1
    out = out.replace("$RepresentationID$", rep.get("id") or "")
    out = out.replace("$Bandwidth$", rep.get("bandwidth") or "")
    out = out.replace("$Number$", str(start + number - 1))
    out = re.sub(
        r"\$Number%(\d+)d\$",
        lambda m: str(start + number - 1).zfill(int(m.group(1))),
        out,
    )
    return out

def find_inherited(elem, name, parent_map):
    node = elem
    while node is not None:
        el = first_child(node, name)
        if el is not None:
            return el
        node = parent_map.get(node)
    return None

def resolve_representation_url(manifest_url, rep, parent_map):
    chain = []
    node = rep
    while node is not None:
        base_el = first_child(node, "BaseURL")
        if base_el is not None and base_el.text and base_el.text.strip():
            chain.append(base_el.text.strip())
        node = parent_map.get(node)
    chain.reverse()
    url = manifest_url
    for part in chain:
        url = urljoin(url, part) if part else url
    return url

def get_init_location(manifest_url, rep, parent_map):
    """Return (url, mode, init_range_or_none) for a representation's init segment."""
    url = resolve_representation_url(manifest_url, rep, parent_map)
    seg_base = find_inherited(rep, "SegmentBase", parent_map)
    if seg_base is not None:
        init_el = first_child(seg_base, "Initialization")
        if init_el is not None:
            rng = (init_el.get("range") or "").strip()
            if rng:
                return url, "range", rng
    seg_tpl = find_inherited(rep, "SegmentTemplate", parent_map)
    if seg_tpl is not None and seg_tpl.get("initialization"):
        init_url = urljoin(url, fill_segment_template(seg_tpl.get("initialization"), rep, seg_tpl))
        return init_url, "open", None
    return url, "open", None

# -------------------------------------------------------------------
# Capture heuristics (content-type / body based, not URL substrings)
# -------------------------------------------------------------------
def looks_like_manifest_url(url):
    path = urlparse(url).path.lower()
    return path.endswith((".mpd", ".m3u8"))

def is_manifest_response(url, content_type):
    ctype = (content_type or "").lower()
    if "dash+xml" in ctype:
        return True
    if "mpegurl" in ctype or "hls" in ctype:
        return True
    if "xml" in ctype and looks_like_manifest_url(url):
        return True
    return False

def looks_like_license_request(url, method, headers, body, resource_type):
    if method != "POST":
        return False
    if resource_type.lower() not in ("xhr", "fetch", "other", "preflight", "manifest"):
        return False
    if body is None or len(body) < 16:
        return False
    ctype = (headers.get("content-type") or "").lower()
    if ctype and any(t in ctype for t in ("json", "x-www-form-urlencoded", "multipart", "text/")):
        return False
    if "protobuf" in ctype or "octet-stream" in ctype:
        return True
    lower_url = url.lower()
    url_hint = any(k in lower_url for k in ("license", "drm", "widevine", "wvls", "acquire", "cas", "key"))
    try:
        body.decode("utf-8")
        return False
    except UnicodeDecodeError:
        return url_hint

# -------------------------------------------------------------------
# License transaction
# -------------------------------------------------------------------
def sanitize_license_headers(headers):
    out = {}
    for k, v in (headers or {}).items():
        if k.lower() in HOP_BY_HOP_HEADERS:
            continue
        out[k] = v
    # The captured request may not have advertised this; default it.
    if not any(k.lower() == "content-type" for k in out):
        out["Content-Type"] = "application/x-protobuf"
    return out

async def post_with_retry(request_context, url, data, headers, retries=4):
    delay = 1.0
    last_resp = None
    last_exc = None
    for attempt in range(retries):
        try:
            resp = await request_context.post(url, data=data, headers=headers)
        except Exception as exc:
            last_exc = exc
            print(f"   POST attempt {attempt + 1} failed ({exc}); retrying...")
        else:
            if resp.status == 429 or 500 <= resp.status < 600:
                last_resp = resp
                print(f"   got HTTP {resp.status}; retrying in {delay:.0f}s...")
            else:
                return resp
        await asyncio.sleep(delay)
        delay = min(delay * 2, 10.0)
    if last_resp is not None:
        return last_resp
    raise RuntimeError(f"POST failed after {retries} attempts: {last_exc}")

def signed_message_type(body):
    try:
        sm = SignedMessage()
        sm.ParseFromString(body)
        return SignedMessage.MessageType.Name(sm.type)
    except Exception:
        return None

async def provision_service_certificate(cdm, session_id, request_context, url, headers):
    if not hasattr(cdm, "service_certificate_challenge"):
        return False
    try:
        resp = await post_with_retry(request_context, url, cdm.service_certificate_challenge, headers)
        if resp.ok:
            body = await resp.body()
            sm = SignedMessage()
            sm.ParseFromString(body)
            if sm.type == SignedMessage.MessageType.Value("SERVICE_CERTIFICATE"):
                cdm.set_service_certificate(session_id, sm.msg)
                print("   service certificate provisioned ✅")
                return True
    except Exception as exc:
        print(f"   service certificate response could not be used: {exc}")

    # Most providers accept Google's common privacy certificate.
    try:
        cdm.set_service_certificate(session_id, Cdm.common_privacy_cert)
        print("   fell back to the common Google privacy certificate.")
        return True
    except Exception as exc:
        print(f"   could not set common privacy certificate: {exc}")
        return False

async def get_content_key(pssh, license_url, license_headers, request_context,
                          device_key_path, device_client_id_path):
    private_key = Path(device_key_path).read_bytes()
    client_id = Path(device_client_id_path).read_bytes()

    print(f"Using Widevine device files from: {Path(device_key_path).parent}")
    device = Device(
        type_=DeviceTypes.CHROME,
        security_level=3,
        flags=None,
        private_key=private_key,
        client_id=client_id,
    )
    cdm = Cdm.from_device(device)
    session_id = cdm.open()
    headers = sanitize_license_headers(license_headers)
    tried_common_cert = False
    try:
        while True:
            has_cert = cdm.get_service_certificate(session_id) is not None
            challenge = cdm.get_license_challenge(
                session_id, pssh, license_type="STREAMING", privacy_mode=has_cert)

            resp = await post_with_retry(request_context, license_url, challenge, headers)
            if resp.status in (401, 403):
                raise RuntimeError(
                    f"License server returned {resp.status}. "
                    "Session/auth expired - please refresh the page and log in again."
                )
            if not resp.ok:
                raise RuntimeError(f"License request failed: HTTP {resp.status}")

            body = await resp.body()
            msg_type = signed_message_type(body)

            if msg_type == "SERVICE_CERTIFICATE_REQUEST":
                print("   server requested a service certificate; provisioning...")
                if not await provision_service_certificate(
                        cdm, session_id, request_context, license_url, headers):
                    raise RuntimeError("Could not provision a service certificate.")
                continue

            try:
                cdm.parse_license(session_id, body)
            except InvalidLicenseMessage as exc:
                if not tried_common_cert:
                    print("   license rejected; retrying with the common Google privacy certificate...")
                    try:
                        cdm.set_service_certificate(session_id, Cdm.common_privacy_cert)
                    except Exception as cert_exc:
                        raise RuntimeError(f"Could not set privacy certificate: {cert_exc}") from cert_exc
                    tried_common_cert = True
                    continue
                raise RuntimeError(f"License rejected (unexpected response): {exc}") from exc
            except SignatureMismatch as exc:
                raise RuntimeError(
                    "License rejected: signature mismatch (bad device identity or tampered response)."
                ) from exc
            except InvalidContext as exc:
                raise RuntimeError(
                    "License rejected: challenge/response context mismatch."
                ) from exc

            keys = cdm.get_keys(session_id)
            content_keys = [k for k in keys if k.type == "CONTENT"]
            if not content_keys and not tried_common_cert:
                print("   license had no CONTENT key; retrying with the common Google privacy certificate...")
                try:
                    cdm.set_service_certificate(session_id, Cdm.common_privacy_cert)
                except Exception as cert_exc:
                    print(f"   could not set privacy certificate: {cert_exc}")
                tried_common_cert = True
                continue

            if not content_keys:
                got = [k.type for k in keys]
                raise RuntimeError(
                    f"License accepted but no CONTENT key returned (got types: {got}). "
                    "The device identity may be revoked or not entitled to this content."
                )
            return content_keys
    finally:
        cdm.close(session_id)

# -------------------------------------------------------------------
# Helper: parse sidx box
# -------------------------------------------------------------------
def parse_sidx(data):
    offset = 0
    while offset + 8 <= len(data):
        size = struct.unpack_from('>I', data, offset)[0]
        try:
            box_type = data[offset+4:offset+8].decode('ascii')
        except UnicodeDecodeError:
            break
        if box_type == 'sidx':
            if size == 0:
                size = len(data) - offset
            version = struct.unpack_from('B', data, offset+8)[0]

            if version == 0:
                ep_offset  = offset + 20
                fo_offset  = offset + 24
                ref_offset = offset + 28
            else:  # version 1
                ep_offset  = offset + 20
                fo_offset  = offset + 28
                ref_offset = offset + 36

            earliest_pres_time = struct.unpack_from('>I', data, ep_offset)[0]
            first_offset = struct.unpack_from('>I', data, fo_offset)[0]
            reserved = struct.unpack_from('>H', data, ref_offset)[0]
            ref_count = struct.unpack_from('>H', data, ref_offset+2)[0]

            entries = []
            current_offset = first_offset
            pos = ref_offset + 4
            for _ in range(ref_count):
                if pos + 12 > offset + size:
                    break
                ref_word = struct.unpack_from('>I', data, pos)[0]
                ref_type = (ref_word >> 31) & 1
                ref_size = ref_word & 0x7fffffff
                sub_dur = struct.unpack_from('>I', data, pos+4)[0]
                entries.append((current_offset, ref_size))
                current_offset += ref_size
                pos += 12
            return entries, first_offset

        if size == 0:
            break
        offset += size
    return [], 0

# -------------------------------------------------------------------
# Main
# -------------------------------------------------------------------
async def main():
    SCRIPT_DIR = pathlib.Path(__file__).parent.resolve()
    PROFILE_DIR = SCRIPT_DIR / "playwright_chromium_profile"
    priv_path = SCRIPT_DIR / "device_key" / "device_private_key"
    blob_path = SCRIPT_DIR / "device_key" / "device_client_id_blob"
    if not priv_path.is_file() or not blob_path.is_file():
        print("❌ Missing Widevine device files.")
        print(f"   Expected: {priv_path}")
        print(f"   Expected: {blob_path}")
        print("   Please place 'device_private_key' and 'device_client_id_blob'")
        print("   inside the 'device_key' folder next to the script.")
        return

    ffmpeg_bin = resolve_ffmpeg(SCRIPT_DIR)
    if not ffmpeg_bin:
        print_ffmpeg_help()
        return
    print(f"Using ffmpeg: {ffmpeg_bin}")

    async with async_playwright() as p:
        browser_kwargs = resolve_browser(p)
        browser = await p.chromium.launch_persistent_context(
            user_data_dir=PROFILE_DIR,
            headless=False,
            ignore_default_args=[
                "--disable-extensions",
                "--disable-component-update",
            ],
            **browser_kwargs,
        )
        page = await browser.new_page()

        # Login
        await page.goto("https://onlyfans.com/", wait_until='domcontentloaded')
        await page.wait_for_timeout(2000)
        if await page.query_selector('a:has-text("Log in")'):
            print("Please log in – waiting for you...")
            await page.wait_for_selector('a:has-text("Log in")', state='hidden', timeout=0)
            print("Logged in – continuing.")
        else:
            print("Already logged in")

        # ---------- Capture ----------
        captured = {
            'manifest_candidates': [],
            'license_candidates': [],
            'page_url': None,
        }

        def record_manifest(url):
            url_stripped = url
            cands = captured['manifest_candidates']
            if not cands or cands[-1]['url'] != url_stripped:
                cands.append({
                    'url': url_stripped,
                    'page_url': page.url,
                    'at': time.time(),
                })
                print(f">>> Manifest candidate #{len(cands)}: {url_stripped}")
            captured['page_url'] = page.url

        def record_license(url, headers):
            cands = captured['license_candidates']
            if not cands or cands[-1]['url'] != url:
                cands.append({
                    'url': url,
                    'headers': headers,
                    'page_url': page.url,
                    'at': time.time(),
                })
                print(f">>> License candidate #{len(cands)}: {url}")
            captured['page_url'] = page.url

        async def on_request(request):
            url = request.url
            method = (request.method or "").upper()
            if method == "GET" and looks_like_manifest_url(url):
                record_manifest(url)
            elif method == "POST":
                body = request.post_data_buffer
                headers = dict(request.headers)
                if looks_like_license_request(
                        url, method, headers, body, request.resource_type):
                    record_license(url, headers)

        async def on_response(response):
            url = response.url
            ctype = (response.headers.get('content-type') or "")
            if is_manifest_response(url, ctype):
                record_manifest(url)

        page.on('request', on_request)
        page.on('response', on_response)

        def current_manifest():
            cands = captured['manifest_candidates']
            return cands[-1] if cands else None

        def current_license():
            cands = captured['license_candidates']
            return cands[-1] if cands else None

        print("Play any DRM video and it will automatically download.")
        print("(Capture is based on resource/content type; the most recent match wins.)")

        try:
            btn = await page.wait_for_selector('[class*="play"], [class*="video"]', timeout=4000)
            await btn.click()
        except Exception as exc:
            print(f"   Could not auto-click a play control ({exc}); waiting for you to play a video.")

        # ---------- Helper: process a detected video ----------
        async def process_video(manifest, license_c):
            print("Processing video...")
            manifest_url = manifest['url']
            license_url = license_c['url']
            license_headers = license_c.get('headers') or {}

            parsed = urlparse(manifest_url)
            output_name = Path(parsed.path).name or "video"
            if output_name.lower().endswith(".mpd"):
                output_name = output_name[:-4] + "_source.mp4"
            elif output_name.lower().endswith(".m3u8"):
                output_name = output_name[:-5] + "_source.mp4"
            else:
                output_name += "_source.mp4"
            downloads_dir = SCRIPT_DIR / "Downloads"
            downloads_dir.mkdir(parents=True, exist_ok=True)
            output_file = downloads_dir / output_name

            if output_file.exists():
                answer = input(f"{output_name} already exists. Overwrite? [y/N] ")
                if answer.lower() != 'y':
                    print(f"{output_name} skipped.")
                    return

            referer = (manifest.get('page_url') or captured.get('page_url')
                       or 'https://onlyfans.com/')
            try:
                ua = await page.evaluate("navigator.userAgent")
            except Exception:
                ua = "Mozilla/5.0"

            manifest_resp = await page.request.get(
                manifest_url, headers={'Referer': referer, 'User-Agent': ua})
            if not manifest_resp.ok:
                print(f"❌ Manifest fetch failed: HTTP {manifest_resp.status}")
                return
            mpd_text = await manifest_resp.text()
            try:
                root = ET.fromstring(mpd_text)
            except ET.ParseError as exc:
                print(f"❌ Manifest is not valid DASH XML: {exc}")
                print("   (HLS/.m3u8 capture is detected, but download is DASH-only for now.)")
                return

            parent_map = build_parent_map(root)
            all_reps = list(iter_desc(root, 'Representation'))

            def find_rep(rep_id):
                for rep in all_reps:
                    if rep.get('id') == rep_id:
                        return rep
                return None

            video_rep = find_rep('1')
            audio_rep = find_rep('4')
            if video_rep is None and all_reps:
                video_rep = all_reps[0]
            if audio_rep is None and len(all_reps) > 1:
                audio_rep = all_reps[1] if all_reps[1] is not video_rep else None

            async def fetch_init_segment(rep):
                if rep is None:
                    return None
                url, mode, rng = get_init_location(manifest_url, rep, parent_map)
                headers = {'Referer': referer, 'User-Agent': ua}
                if mode == 'range' and rng:
                    headers['Range'] = f"bytes={rng}"
                resp = await page.request.get(url, headers=headers)
                if resp.ok:
                    return await resp.body()
                print(f"   init segment fetch failed: HTTP {resp.status} ({url})")
                return None

            # ---------- PSSH ----------
            pssh_bytes = extract_manifest_pssh(root)
            if pssh_bytes:
                print("Widevine PSSH extracted from manifest ✅")
            else:
                reps_to_try = []
                for r in [video_rep, audio_rep] + all_reps:
                    if r is not None and all(r is not x for x in reps_to_try):
                        reps_to_try.append(r)
                for rep in reps_to_try:
                    init_data = await fetch_init_segment(rep)
                    if not init_data:
                        continue
                    wv_boxes = find_widevine_pssh_boxes(init_data)
                    if wv_boxes:
                        pssh_bytes = wv_boxes[0]
                        print("Widevine PSSH extracted from init segment ✅")
                        break

            if not pssh_bytes:
                print("   no Widevine PSSH in manifest or init segment; trying PlayReady mspr:pro...")
                pssh_bytes = extract_playready_pssh(root)
                if pssh_bytes:
                    print("PSSH converted from PlayReady ✅")

            if not pssh_bytes:
                print("   scanning manifest text for a base64 PSSH blob...")
                pssh_bytes = pssh_fallback_from_text(mpd_text)
                if pssh_bytes:
                    print("PSSH found via manifest text scan ✅")

            if not pssh_bytes:
                print("❌ No Widevine PSSH found (manifest, init segment, or PlayReady).")
                return

            try:
                pssh_obj = PSSH(pssh_bytes)
            except Exception as exc:
                print(f"❌ Could not parse PSSH: {exc}")
                return

            # ---------- License ----------
            content_keys = await get_content_key(
                pssh_obj, license_url, license_headers, page.request,
                str(priv_path), str(blob_path))

            def rep_kid_hint(rep):
                if rep is None:
                    return None
                node = rep
                while node is not None:
                    for cp in iter_children(node):
                        if local(cp.tag) == 'ContentProtection':
                            val = cp.get(CENC_DEFAULT_KID) or cp.get('default_KID')
                            if val:
                                return normalize_kid(val)
                    node = parent_map.get(node)
                return None

            def pick_key(kid_hint):
                hint = normalize_kid(kid_hint)
                if hint:
                    for k in content_keys:
                        if k.kid == hint:
                            return k
                pssh_kids = []
                try:
                    pssh_kids = list(pssh_obj.key_ids)
                except Exception:
                    pssh_kids = []
                for pid in pssh_kids:
                    for k in content_keys:
                        if k.kid == pid:
                            return k
                if len(content_keys) == 1:
                    return content_keys[0]
                print("   ⚠ multiple CONTENT keys and no KID match; using the first one.")
                return content_keys[0]

            video_key = pick_key(rep_kid_hint(video_rep))
            print(f"Video Key ID: {video_key.kid}")
            audio_key = pick_key(rep_kid_hint(audio_rep)) if audio_rep is not None else None
            if audio_key is not None:
                print(f"Audio Key ID: {audio_key.kid}")

            # ---------- Download representations ----------
            async def fetch_rng(url, s, e):
                headers = {
                    'Range': f'bytes={s}-{e}',
                    'Referer': referer,
                    'User-Agent': ua,
                }
                resp = await page.request.get(url, headers=headers)
                if resp.ok:
                    return await resp.body()
                raise RuntimeError(f"Range {s}-{e} of {url} failed: HTTP {resp.status}")

            async def download_representation(rep, prefix):
                if rep is None:
                    print(f"  [{prefix}] representation not found – skipping")
                    return None
                url = resolve_representation_url(manifest_url, rep, parent_map)
                seg_base = find_inherited(rep, 'SegmentBase', parent_map)
                if seg_base is None or not seg_base.get('indexRange'):
                    print(f"  [{prefix}] no SegmentBase/indexRange (only SegmentBase is supported) – skipping")
                    return None
                idx_s, idx_e = (int(x) for x in seg_base.get('indexRange').split('-'))
                init_el = first_child(seg_base, 'Initialization')
                if init_el is None or not init_el.get('range'):
                    print(f"  [{prefix}] no Initialization range – skipping")
                    return None
                init_s, init_e = (int(x) for x in init_el.get('range').split('-'))

                print(f"  [{prefix}] init {init_s}-{init_e}")
                init_data = await fetch_rng(url, init_s, init_e)
                print(f"  [{prefix}] index {idx_s}-{idx_e}")
                idx_data = await fetch_rng(url, idx_s, idx_e)

                entries, first_offset = parse_sidx(idx_data)
                anchor = idx_e + 1

                if not entries:
                    print(f"  [{prefix}] no sidx – downloading open-ended")
                    open_resp = await page.request.get(url, headers={
                        'Range': f'bytes={init_e+1}-',
                        'Referer': referer,
                        'User-Agent': ua,
                    })
                    if open_resp.ok:
                        media_data = await open_resp.body()
                    else:
                        raise RuntimeError(f"open range failed: HTTP {open_resp.status}")
                else:
                    total = len(entries)
                    print(f"  [{prefix}] {total} subsegments")
                    parts = []
                    for i, (start, length) in enumerate(entries):
                        abs_start = anchor + start
                        end = abs_start + length - 1
                        pct = (i + 1) / total * 100
                        bar = '█' * int(pct // 2) + '░' * (50 - int(pct // 2))
                        print(f"\r    [{bar}] {pct:.1f}%", end='')
                        parts.append(await fetch_rng(url, abs_start, end))
                    print()
                    media_data = b''.join(parts)

                fpath = SCRIPT_DIR / f"{prefix}_enc.mp4"
                Path(fpath).write_bytes(init_data + media_data)
                print(f"  [{prefix}] saved {fpath}")
                return fpath

            video_file = await download_representation(video_rep, 'video')
            audio_file = await download_representation(audio_rep, 'audio')

            if not video_file:
                print("❌ No video downloaded")
                return

            # ---------- Mux ----------
            cmd = [ffmpeg_bin, '-y',
                   '-decryption_key', video_key.key.hex(), '-i', str(video_file)]
            if audio_file and audio_key is not None:
                cmd += ['-decryption_key', audio_key.key.hex(), '-i', str(audio_file)]
            cmd += ['-c', 'copy', str(output_file)]
            try:
                subprocess.run(cmd, check=True)
            except FileNotFoundError:
                print(f"ffmpeg could not be executed: {ffmpeg_bin}")
                print_ffmpeg_help()
                return
            except subprocess.CalledProcessError as e:
                print(f"ffmpeg failed with exit code {e.returncode}")
                print("   Temporary files kept for inspection:")
                print(f"   {video_file}")
                if audio_file:
                    print(f"   {audio_file}")
                return

            # Cleanup
            for tf in (video_file, audio_file):
                if tf:
                    try:
                        Path(tf).unlink()
                    except (FileNotFoundError, OSError):
                        pass

            print(f"✅ {output_name} saved to {downloads_dir}")
            print("Play another video to download, or close the browser to exit.\n")

        # ---------- Main loop ----------
        QUIET_SECONDS = 2.0
        while True:
            if page.is_closed():
                print("Browser closed – exiting.")
                break

            manifest = current_manifest()
            license_candidate = current_license()
            if manifest and license_candidate:
                latest = max(manifest['at'], license_candidate['at'])
                # Debounce so a preroll captured moments before the real stream
                # doesn't preempt the video you intended to play.
                if time.time() - latest >= QUIET_SECONDS:
                    await process_video(manifest, license_candidate)
                    captured['manifest_candidates'].clear()
                    captured['license_candidates'].clear()
                    continue
            await asyncio.sleep(0.5)

        await browser.close()

if __name__ == '__main__':
    asyncio.run(main())