import json
import time
from pathlib import Path
from mitmproxy import http, ctx
import math
import random, string

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
        if "http_split_old" in mutations:       # usa {"num_chunks": 3, "uniform": true}
            split_cfg = mutations["http_split"]
            if isinstance(split_cfg, str):
                split_cfg = json.loads(split_cfg)

            # Evita di applicare due volte se la richiesta è già chunked
            if flow.request.headers.get("Transfer-Encoding", "").lower() == "chunked":
                print("[Mitmproxy] Richiesta già chunked, salto http_split")
                return

            num_chunks = split_cfg.get("num_chunks", 5)
            uniform = split_cfg.get("uniform", False)

            body = flow.request.content
            if not body:
                return

            total_len = len(body)
            chunks = []

            if uniform:
                # Divisione uniforme
                base = total_len // num_chunks
                remainder = total_len % num_chunks
                pos = 0
                for i in range(num_chunks):
                    chunk_len = base + (1 if i < remainder else 0)
                    chunks.append(body[pos:pos+chunk_len])
                    pos += chunk_len
            else:
                # Divisione casuale (ma somma al totale)
                if total_len <= num_chunks:
                    # Se il body è più piccolo del numero di chunk, crea chunk da 1 byte
                    chunks = [body[i:i+1] for i in range(total_len)]
                else:
                    cuts = sorted(random.sample(range(1, total_len), num_chunks - 1))
                    pos = 0
                    for cut in cuts:
                        chunks.append(body[pos:cut])
                        pos = cut
                    chunks.append(body[pos:])

            # Costruzione del corpo chunked (standard)
            new_body = b""
            for chunk in chunks:
                chunk_len_hex = f"{len(chunk):x}".encode()
                new_body += chunk_len_hex + b"\r\n" + chunk + b"\r\n"
            new_body += b"0\r\n\r\n"

            new_body = b"AAA"

            print(f"new body: {new_body}")

            # Applica gli header e sostituisci il contenuto
            flow.request.headers["Transfer-Encoding"] = "chunked"
            flow.request.headers.pop("Content-Length", None)
            flow.request.content = new_body
            print("CONTENT LEN:", len(flow.request.content))
            print("CONTENT RAW:", flow.request.content)

            print(f"[Mitmproxy] HTTP split: {len(chunks)} chunks, body {total_len} -> {len(new_body)} bytes")
        
        if "http_split_old2" in mutations:      # usa {"chunk_size": 13, "extensions": false}
            split_cfg = mutations["http_split"]
            if isinstance(split_cfg, str):
                split_cfg = json.loads(split_cfg)

            # Parametri: chunk_size (default 13), extensions (default True)
            chunk_size = split_cfg.get("chunk_size", 13)
            use_extensions = split_cfg.get("extensions", True)

            # Ottieni il body della richiesta
            body = flow.request.content
            if not body:
                return

            # Decodifica il body in stringa (assumiamo UTF-8)
            try:
                text = body.decode('utf-8')
            except UnicodeDecodeError:
                # Se non è UTF-8, lascia perdere
                return

            # Costruzione del nuovo body chunked con extension
            new_body = ""
            for i in range(0, len(text), chunk_size):
                chunk = text[i:i+chunk_size]
                print(f"Chunk: {chunk}")
                chunk_len_hex = f"{len(chunk):x}"
                if use_extensions:
                    # Genera estensione casuale di 10 caratteri alfanumerici
                    ext = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
                    new_body += f"{chunk_len_hex};{ext}\r\n{chunk}\r\n"
                else:
                    new_body += f"{chunk_len_hex}\r\n{chunk}\r\n"
            new_body += "0\r\n\r\n"
            print(f"New body: {new_body}")

            # Applica le modifiche alla richiesta
            flow.request.headers["Transfer-Encoding"] = "chunked"
            # Rimuovi Content-Length (incompatibile con chunked)
            flow.request.headers.pop("Content-Length", None)
            # Opzionale: aggiungi header 'test' per evitare loop (come nel codice originale)
            flow.request.headers["X-Chunked-Evasion"] = "1"
            flow.request.content = new_body.encode('utf-8')

            print(f"[Mitmproxy] HTTP split con chunk size={chunk_size}, extensions={use_extensions}")

addons = [EvasionAddon()]