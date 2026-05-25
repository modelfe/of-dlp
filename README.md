# of-dlp

A Python + Playwright tool to decrypt and download OnlyFans DRM content

---

**IMPORTANT**: You must provide your own Widevine decryption files (```device_private_key``` and ```device_client_id_blob```) to use this script.

**Requirements**:
- Python 3
- ffmpeg
- Windows users only: if you get a "DLL load failed while importing _greenlet" error when running it, you may need to install the [Visual C++ runtime DLLs](https://aka.ms/vs/17/release/vc_redist.x64.exe)

**Instructions**:
1. [Download](https://codeberg.org/cbxcgdxfbc/of-dlp/src/branch/main/of-dlp.py) the script and place it in a folder (e.g. ```/home/user/of-dlp``` or ```C:\Users\YourUsername\of-dlp```).
2. Inside that folder, create a subfolder named ```device_key``` and place your ```device_private_key``` and ```device_client_id_blob``` files in it.
3. Make the script executable (```chmod +x of-dlp.py```) – Linux/macOS only; not needed on Windows.
4. Open terminal (Linux/macOS) or Command Prompt/Powershell (Windows) and run the script: ```python /path/to/of-dlp.py```
5. On first run, a Python virtual environment (.venv) is created automatically, and playwright and pywidevine are installed. A Chromium browser opens to OnlyFans – log in once. Subsequent runs stay logged in.
6. Play any DRM‑protected video on OnlyFans and it will be downloaded automatically to a Downloads subfolder.

**Notes**:

The script does **not** download any non‑DRM content.

It has only been properly tested on Linux, but should also run on macOS and Windows. If not, create an Issue.

This script is intended for personal use only. Downloading or redistributing copyrighted material may violate OnlyFans' Terms of Service and applicable laws. You are solely responsible for your use of this tool.

UPDATES:
- 24 May 2026 - Playwright now uses the system-installed Google Chrome by default (or, if not installed, Edge, Chrome Beta, Chrome Dev, Chrome Canary, in that order of preference), because the Playwright-installed Chromium does not include required Widevine modules by default. Alternative Chromium installations (e.g. Brave, Chromium, etc.) can be specified at the top of the script in the Browser configuration section by providing the path to the browser executable.
- 25 May 2026 - fixed bug where Playwright was launching Chrome with "--disable-component-update", which prevented Widevine DRM playback on Windows.