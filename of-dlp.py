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
        subprocess.check_call([str(bin_dir / "playwright"), "install", "chromium"])

if sys.prefix != str(VENV_DIR):
    setup_venv()
    if os.name == "nt":
        python = str(VENV_DIR / "Scripts" / "python.exe")
    else:
        python = str(VENV_DIR / "bin" / "python")
    os.execv(python, [python, *sys.argv])

import asyncio
import base64
import re
import subprocess
import xml.etree.ElementTree as ET
import struct
from pathlib import Path
from urllib.parse import urljoin, urlparse
from playwright.async_api import async_playwright
from pywidevine import Device, DeviceTypes, Cdm, PSSH

# -------------------------------------------------------------------
# 1. Decrypt license
# -------------------------------------------------------------------
async def get_content_key(pssh_data, license_url, license_headers,
                          request_context,
                          device_key_path, device_client_id_path):
    with open(device_key_path, 'rb') as f:
        private_key = f.read()
    with open(device_client_id_path, 'rb') as f:
        client_id = f.read()

    device = Device(
        type_=DeviceTypes.CHROME,
        security_level=3,
        flags=None,
        private_key=private_key,
        client_id=client_id,
    )
    cdm = Cdm.from_device(device)
    pssh = PSSH(pssh_data)
    session_id = cdm.open()
    challenge = cdm.get_license_challenge(session_id, pssh)

    skip = {'host', 'content-length', 'transfer-encoding',
            'accept-encoding', 'connection', 'keep-alive', 'cookie'}
    filtered = {k: v for k, v in license_headers.items() if k.lower() not in skip}

    resp = await request_context.post(license_url, data=challenge, headers=filtered)
    if not resp.ok:
        raise Exception(f"License failed: {resp.status}")
    license_response = await resp.body()

    cdm.parse_license(session_id, license_response)
    keys = cdm.get_keys(session_id)
    content_key = next((k for k in keys if k.type == 'CONTENT'), None)
    cdm.close(session_id)
    if not content_key:
        raise RuntimeError("No content key")
    return content_key.kid, content_key.key

# -------------------------------------------------------------------
# 2. Helper: parse sidx box
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
# 3. Main
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

    async with async_playwright() as p:
        browser = await p.chromium.launch_persistent_context(
            user_data_dir=PROFILE_DIR,
            headless=False,
            args=["--enable-widevine"],
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
        captured = {'manifest_url': None, 'license_url': None,
                     'license_headers': None, 'pssh': None, 'page_url': None}

        async def on_request(request):
            url = request.url
            if '.mpd' in url:
                captured['manifest_url'] = url
                captured['page_url'] = page.url
                print(">>> Manifest captured")
            if '/drm/' in url:
                captured['license_url'] = url
                captured['license_headers'] = dict(request.headers)
                captured['page_url'] = page.url

        page.on('request', on_request)

        print("Play any DRM video and it will automatically download")
        await page.wait_for_timeout(5000)
        try:
            btn = await page.wait_for_selector('[class*="play"], [class*="video"]', timeout=4000)
            await btn.click()
        except:
            pass

        while True:
            if page.is_closed():
                print("Browser closed – exiting.")
                await browser.close()
                return
            if captured['manifest_url'] and captured['license_url']:
                break
            await asyncio.sleep(1)

        if not captured['manifest_url'] or not captured['license_url']:
            print("❌ Capturing failed"); await browser.close(); return

        # ---------- Helper: process a detected video ----------
        async def process_video():
            nonlocal captured
            print("Processing video...")

            # Build the output path and check for existence
            parsed = urlparse(captured['manifest_url'])
            output_name = Path(parsed.path).name.replace('.mpd', '_source.mp4')
            downloads_dir = SCRIPT_DIR / "Downloads"
            downloads_dir.mkdir(parents=True, exist_ok=True)
            output_file = downloads_dir / output_name

            if output_file.exists():
                answer = input(f"{output_name} already exists. Overwrite? [y/N] ")
                if answer.lower() != 'y':
                    print(f"{output_name} Skipped.")
                    print("Play any DRM video and it will automatically download")
                    return

            # Fetch manifest
            mpd_resp = await page.request.get(captured['manifest_url'],
                headers={'Referer': captured.get('page_url', 'https://onlyfans.com/'),
                         'User-Agent': await page.evaluate("navigator.userAgent")})
            mpd_text = await mpd_resp.text()
            root = ET.fromstring(mpd_text)
            ns = {'mpd': 'urn:mpeg:dash:schema:mpd:2011',
                  'cenc': 'urn:mpeg:cenc:2013'}

            # PSSH
            pssh_found = False
            for cp in root.findall('.//mpd:ContentProtection', ns):
                if cp.get('schemeIdUri') == 'urn:uuid:edef8ba9-79d6-4ace-a3c8-27dcd51d21ed':
                    pe = cp.find('cenc:pssh', ns)
                    if pe is not None and pe.text:
                        raw = re.sub(r'<!\[CDATA\[(.*?)\]\]>', r'\1', pe.text.strip(), flags=re.DOTALL)
                        captured['pssh'] = base64.b64decode(raw)
                        pssh_found = True
                        print("Widevine PSSH extracted ✅")
                        break
            if not pssh_found:
                print("❌ No Widevine PSSH")
                return

            # License
            priv_path = SCRIPT_DIR / "device_key" / "device_private_key"
            blob_path = SCRIPT_DIR / "device_key" / "device_client_id_blob"
            kid, key = await get_content_key(
                captured['pssh'], captured['license_url'], captured['license_headers'],
                page.request,
                str(priv_path), str(blob_path))
            print(f"Key ID: {kid}")
            key_hex = key.hex()

            # Download representations
            def find_rep_url(rep_id):
                rep = root.find(f'.//mpd:Representation[@id="{rep_id}"]', ns)
                if rep is None:
                    return None
                base_el = rep.find('mpd:BaseURL', ns)
                if base_el is None:
                    return None
                return urljoin(captured['manifest_url'], base_el.text.strip())

            async def download_representation(rep_id, prefix):
                url = find_rep_url(rep_id)
                if url is None:
                    print(f"  [{prefix}] representation not found – skipping")
                    return None

                rep = root.find(f'.//mpd:Representation[@id="{rep_id}"]', ns)
                seg_base = rep.find('mpd:SegmentBase', ns)
                idx_s, idx_e = map(int, seg_base.get('indexRange', '').split('-'))
                init_s, init_e = map(int, seg_base.find('mpd:Initialization', ns).get('range', '').split('-'))

                async def fetch_rng(s, e):
                    headers = {'Range': f'bytes={s}-{e}',
                               'Referer': captured.get('page_url', 'https://onlyfans.com/'),
                               'User-Agent': await page.evaluate("navigator.userAgent")}
                    resp = await page.request.get(url, headers=headers)
                    if resp.ok:
                        return await resp.body()
                    raise Exception(f"Range {s}-{e} failed: {resp.status}")

                print(f"  [{prefix}] init {init_s}-{init_e}")
                init_data = await fetch_rng(init_s, init_e)
                print(f"  [{prefix}] index {idx_s}-{idx_e}")
                idx_data = await fetch_rng(idx_s, idx_e)

                entries, first_offset = parse_sidx(idx_data)
                anchor = idx_e + 1

                if not entries:
                    print(f"  [{prefix}] no sidx – downloading open-ended")
                    resp = await page.request.get(url, headers={
                        'Range': f'bytes={init_e+1}-',
                        'Referer': captured.get('page_url', 'https://onlyfans.com/'),
                        'User-Agent': await page.evaluate("navigator.userAgent")})
                    if resp.ok:
                        media_data = await resp.body()
                    else:
                        raise Exception("open range failed")
                else:
                    total = len(entries)
                    print(f"  [{prefix}] {total} subsegments")
                    parts = []
                    for i, (start, length) in enumerate(entries):
                        abs_start = anchor + start
                        end = abs_start + length - 1
                        # Terminal progress bar
                        pct = (i + 1) / total * 100
                        bar = '█' * int(pct // 2) + '░' * (50 - int(pct // 2))
                        print(f"\r    [{bar}] {pct:.1f}%", end='')
                        parts.append(await fetch_rng(abs_start, end))
                    print()  # newline after done
                    media_data = b''.join(parts)

                fname = f"{prefix}_enc.mp4"
                with open(fname, "wb") as f:
                    f.write(init_data)
                    f.write(media_data)
                print(f"  [{prefix}] saved {fname}")
                return fname

            video_file = await download_representation('1', 'video')
            audio_file = await download_representation('4', 'audio')

            if not video_file:
                print("❌ No video downloaded")
                return

            # Mux
            cmd = ['ffmpeg', '-y', '-decryption_key', key_hex, '-i', video_file]
            if audio_file:
                cmd += ['-decryption_key', key_hex, '-i', audio_file]
            cmd += ['-c', 'copy', str(output_file)]
            subprocess.run(cmd, check=True)

            # Cleanup
            for tf in ["video_enc.mp4", "audio_enc.mp4"]:
                try:
                    Path(tf).unlink()
                except FileNotFoundError:
                    pass

            print(f"✅ {output_name} saved to {downloads_dir}")
            print("Play another video to download, or close the browser to exit.\n")

        # ---------- Main loop: wait for videos ----------
        while True:
            if page.is_closed():
                await asyncio.sleep(1)
                print("Browser closed – exiting.")
                break
            if captured['manifest_url'] and captured['license_url']:
                await process_video()
                # Reset captures for next video
                captured['manifest_url'] = None
                captured['license_url'] = None
                captured['license_headers'] = None
                captured['pssh'] = None
            await asyncio.sleep(1)

        await browser.close()

if __name__ == '__main__':
    asyncio.run(main())