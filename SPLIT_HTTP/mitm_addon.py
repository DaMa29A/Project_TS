import json
import time
from pathlib import Path
from mitmproxy import http

SHARED_FILE = Path("current_l7_mutation.json")

class EvasionAddon:

    def request(self, flow: http.HTTPFlow):
        if not SHARED_FILE.exists():
            return

        try:
            with open(SHARED_FILE, "r") as f:
                mutations = json.load(f)

            # -------------------------------------------------
            # USER-AGENT
            # -------------------------------------------------
            if "user_agent" in mutations:
                new_ua = str(mutations["user_agent"])
                flow.request.headers["User-Agent"] = new_ua
                print(f"[Mitmproxy] User-Agent -> {new_ua[:40]}")

            # -------------------------------------------------
            # ACCEPT-LANGUAGE
            # -------------------------------------------------
            if "accept_language" in mutations:
                new_al = str(mutations["accept_language"])
                flow.request.headers["Accept-Language"] = new_al
                print(f"[Mitmproxy] Accept-Language -> {new_al}")

            # -------------------------------------------------
            # HTTP SPLIT (Chunked Transfer Encoding)
            # -------------------------------------------------
            if "http_split" in mutations:
                split_data = mutations["http_split"]
                chunk_size = int(split_data.get("chunk_size", 8))
                delay_ms = int(split_data.get("delay_ms", 50))

                body = flow.request.raw_content
                if not body:
                    return

                chunks = [body[i:i + chunk_size] for i in range(0, len(body), chunk_size)]

                # Abilita chunked transfer
                flow.request.headers["Transfer-Encoding"] = "chunked"
                if "Content-Length" in flow.request.headers:
                    del flow.request.headers["Content-Length"]

                new_body = b""
                for chunk in chunks:
                    # Delay artificiale (utile se si usa streaming reale, in mitmproxy ritarda solo la composizione)
                    time.sleep(delay_ms / 1000)
                    chunk_len = hex(len(chunk))[2:].encode()
                    new_body += chunk_len + b"\r\n" + chunk + b"\r\n"
                
                new_body += b"0\r\n\r\n"

                flow.request.raw_content = new_body

                print(
                    f"[Mitmproxy] HTTP split applicato | "
                    f"chunks={len(chunks)} | "
                    f"chunk_size={chunk_size}"
                )

        except Exception as e:
            print(f"[Mitmproxy] Errore: {e}")

addons = [EvasionAddon()]