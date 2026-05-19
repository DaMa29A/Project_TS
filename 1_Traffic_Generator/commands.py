import subprocess
import shutil
import sys
import requests
import random
import time
import urllib3
from constants import USER_AGENTS, ACCEPT_LANGUAGES

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
VERIFY_TLS = False

def find_chrome_binary():
    candidates = [
        "google-chrome",
        "chromium",
        "chromium-browser",
        "chrome",
    ]
    for name in candidates:
        path = shutil.which(name)
        if path:
            return path
    return None

def check_commands():
    if shutil.which("curl") is None:
        print("[!] curl non trovato nel PATH", file=sys.stderr)
        sys.exit(1)

    print(f"\n[+] curl trovato: {shutil.which('curl')}")

    chrome_bin = find_chrome_binary()
    if chrome_bin is None:
        print("[!] Chrome/Chromium non trovato nel PATH", file=sys.stderr)
        sys.exit(1)
    
    print(f"[+] browser headless trovato: {chrome_bin}")

    return None, chrome_bin


##################################### Commands #####################################
def run_curl(url):
    cmd = [
        "curl",
        "-A", random.choice(USER_AGENTS),
        "-H", f"Accept-Language: {random.choice(ACCEPT_LANGUAGES)}",
        "-L",               # Follow redirects
        "-s",               # Silent mode
        "-o", "/dev/null",  # Output discard
        "-w",               # Write output custom
        "%{http_code} %{size_download} %{content_type}\n",
    ]

    if url.startswith("https://") and not VERIFY_TLS:
        cmd.append("-k")

    cmd.append(url)

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=30
    )

    output = result.stdout.strip() if result.stdout else ""
    error = result.stderr.strip() if result.stderr else ""

    if result.returncode == 0:
        print(f"[curl]   {url} -> {output}")
    else:
        print(f"[curl]   {url} -> ERROR rc={result.returncode} {error}")



def run_chrome(url, chrome_bin):
    cmd = [
        chrome_bin,
        "--headless",       # Modalità senza GUI
        "--disable-gpu",    # No gpu
        "--dump-dom",       # implica che: la pagina viene caricata e asset vengono richiesti (CSS, immagini)
        "--no-sandbox",        
    ]

    if url.startswith("https://") and not VERIFY_TLS:
        cmd.append("--ignore-certificate-errors")

    cmd.append(url)

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=45
    )

    if result.returncode == 0:
        dom_size = len(result.stdout or "")
        print(f"[chrome] {url} -> DOM {dom_size} bytes")
    else:
        error = result.stderr.strip() if result.stderr else ""
        print(f"[chrome] {url} -> ERROR rc={result.returncode} {error}")


def run_requests(url):
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept-Language": random.choice(ACCEPT_LANGUAGES),
        "Connection": "keep-alive",
    }

    method = "GET"
    if random.random() < 0.15:
        method = "HEAD"

    try:
        start = time.time()

        if method == "GET":
            response = requests.get(
                url,
                headers=headers,
                timeout=10,
                verify=VERIFY_TLS
            )
        else:
            response = requests.head(
                url,
                headers=headers,
                timeout=10,
                verify=VERIFY_TLS
            )

        elapsed = (time.time() - start) * 1000

        size = len(response.content) if method == "GET" else 0

        print(
            f"[requests] {method} {url} -> "
            f"{response.status_code} {size}B {elapsed:.1f}ms"
        )

    except requests.exceptions.RequestException as exc:
        print(f"[requests] {method} {url} -> ERROR: {exc}")