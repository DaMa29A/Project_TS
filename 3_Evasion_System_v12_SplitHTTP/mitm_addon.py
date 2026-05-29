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
                mutation = json.load(f)

            field = mutation.get("field_to_mutate")
            value = mutation.get("new_value", {})

            # -------------------------------------------------
            # USER-AGENT
            # -------------------------------------------------

            if field == "user_agent":

                new_ua = str(value)

                flow.request.headers["User-Agent"] = new_ua

                print(f"[Mitmproxy] User-Agent -> {new_ua[:40]}")

            # -------------------------------------------------
            # ACCEPT-LANGUAGE
            # -------------------------------------------------

            elif field == "accept_language":

                new_al = str(value)

                flow.request.headers["Accept-Language"] = new_al

                print(f"[Mitmproxy] Accept-Language -> {new_al}")

            # -------------------------------------------------
            # HTTP SPLIT
            # -------------------------------------------------

            elif field == "http_split":

                chunk_size = int(value.get("chunk_size", 8))
                delay_ms = int(value.get("delay_ms", 50))

                body = flow.request.raw_content

                if not body:
                    return

                chunks = []

                for i in range(0, len(body), chunk_size):
                    chunks.append(body[i:i + chunk_size])

                # abilita chunked transfer
                flow.request.headers["Transfer-Encoding"] = "chunked"

                if "Content-Length" in flow.request.headers:
                    del flow.request.headers["Content-Length"]

                new_body = b""

                for chunk in chunks:

                    # delay artificiale
                    time.sleep(delay_ms / 1000)

                    chunk_len = hex(len(chunk))[2:].encode()

                    new_body += chunk_len + b"\r\n"
                    new_body += chunk + b"\r\n"

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