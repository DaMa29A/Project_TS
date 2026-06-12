import json
import time
from pathlib import Path
from mitmproxy import http, ctx
import math
import random

SHARED_FILE = Path("current_l7_mutation.json")

class EvasionAddon:
    def request(self, flow: http.HTTPFlow):
        # Anti-loop
        if "X-Is-Replayed" in flow.request.headers:
            return
        if not SHARED_FILE.exists():
            return

        try:
            with open(SHARED_FILE, "r") as f:
                mutations = json.load(f)
        except Exception as e:
            print(f"[Mitmproxy] Errore lettura file: {e}")
            return

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
        # REFERER
        # -------------------------------------------------
        if "referer" in mutations:
            new_ref = str(mutations["referer"])
            flow.request.headers["Referer"] = new_ref
            print(f"[Mitmproxy] Referer -> {mutations['referer']}")

        # -------------------------------------------------
        # CONTENT-TYPE
        # -------------------------------------------------
        if "content_type" in mutations:
            new_cont = str(mutations["content_type"])
            flow.request.headers["Content-Type"] = new_cont
            print(f"[Mitmproxy] Content-Type -> {mutations['content_type']}")

        # -------------------------------------------------
        # CHUNKED TRANSFER ENCODING
        # -------------------------------------------------
        """if "http_split" in mutations:
                split_data = mutations["http_split"]

                if isinstance(split_data, str):
                    split_data = json.loads(split_data)
                else:
                    split_data = split_data

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
                    chunk_len = hex(len(chunk))[2:].encode()
                    new_body += chunk_len + b"\r\n" + chunk + b"\r\n"
                
                new_body += b"0\r\n\r\n"

                flow.request.raw_content = new_body

                print(
                    f"[Mitmproxy] HTTP split applicato | "
                    f"chunks={len(chunks)} | "
                    f"chunk_size={chunk_size}"
                )"""
        if "http_split" in mutations:
            split_cfg = mutations["http_split"]
            if isinstance(split_cfg, str):
                split_cfg = json.loads(split_cfg)
            
            # Parametri: num_chunks (obbligatorio) e opzionalmente chunk_size (se vuoi dimensione fissa)
            num_chunks = split_cfg.get("num_chunks", 5)   # default 5 chunk
            # Se vuoi chunk di dimensione uguale (approssimativa)
            uniform = split_cfg.get("uniform", False)     # se True, divide equamente il body
            
            body = flow.request.content
            if not body:
                return
            
            total_len = len(body)
            chunks = []
            
            if uniform:
                # Dividi il body in num_chunks parti il più possibile uguali
                base = total_len // num_chunks
                remainder = total_len % num_chunks
                pos = 0
                for i in range(num_chunks):
                    chunk_len = base + (1 if i < remainder else 0)
                    chunks.append(body[pos:pos+chunk_len])
                    pos += chunk_len
            else:
                # Numero esatto di chunk, dimensioni casuali ma che alla fine sommano al totale
                # Genera num_chunks - 1 tagli casuali
                import random
                cuts = sorted(random.sample(range(1, total_len), num_chunks - 1))
                pos = 0
                for cut in cuts:
                    chunks.append(body[pos:cut])
                    pos = cut
                chunks.append(body[pos:])
            
            # Costruzione del body chunked
            new_body = b""
            for chunk in chunks:
                chunk_len_hex = hex(len(chunk))[2:].encode()
                new_body += chunk_len_hex + b"\r\n" + chunk + b"\r\n"
            new_body += b"0\r\n\r\n"
            
            # Applica modifiche
            flow.request.headers["Transfer-Encoding"] = "chunked"
            flow.request.headers.pop("Content-Length", None)
            flow.request.content = new_body
            
            print(f"[Mitmproxy] HTTP split: {len(chunks)} chunks, total body {total_len} bytes")

addons = [EvasionAddon()]