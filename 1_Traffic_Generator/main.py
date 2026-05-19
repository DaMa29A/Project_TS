import subprocess
import time
import random
from constants import CHROME_PATHS, TOTAL_ACTIONS, CHROME_RATIO
from commands import run_chrome, run_curl, check_commands, run_requests
from utils import pick_base_target, pick_path, sample_delay


def main():
    _, chrome_bin = check_commands()

    print(f"[+] azioni totali: {TOTAL_ACTIONS}")

    for i in range(1, TOTAL_ACTIONS + 1):
        # curl, chrome o request
        r = random.random()
        if r < CHROME_RATIO:
            client = "chrome"
        elif r < CHROME_RATIO + 0.10:
            client = "curl"
        else:
            client = "requests"


        # Costruzione stringa url
        base = pick_base_target()
        if client == "chrome":
            path = random.choice(CHROME_PATHS)
        else:
            path = pick_path()
        url = f"{base}{path}"

        
        print(f"\n=== ACTION {i:03d} | client={client} ===")

        try:
            if client == "curl":
                run_curl(url)
            elif client == "chrome":
                run_chrome(url, chrome_bin)
            else:
                run_requests(url)
        except subprocess.TimeoutExpired:
            print(f"[{client}] {url} -> TIMEOUT")
        except Exception as exc:
            print(f"[{client}] {url} -> ERROR: {exc}")

        # Pausa
        if i < TOTAL_ACTIONS:
            delay = sample_delay()
            print(f"--- pausa {delay:.2f}s ---")
            time.sleep(delay)


if __name__ == "__main__":
    main()