import json
import time
from pathlib import Path
from mitmproxy import http, ctx
import math

SHARED_FILE = Path("current_l7_mutation.json")

class EvasionAddon:
    def request(self, flow: http.HTTPFlow):
        # STOP LOOP REPLAY (FONDAMENTALE)
        """if flow.request.headers.get("X-Replayed") == "1":
            return"""

        # 1. ANTI-LOOP: Se la richiesta è già stata riprocessata da noi, ignorala
        if "X-Is-Replayed" in flow.request.headers:
            return
         
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
            # Chunked transfer encoding 
            # -------------------------------------------------
            if "http_split" in mutations:
                value = mutations["http_split"]
                print(f"Value 1: {value}")

                if isinstance(value, str):
                    try:
                        print(f"Value is string: {value}")
                        value = json.loads(value)
                        print(f"Value is json now: {value}")
                    except json.JSONDecodeError:
                        print(f"[Mitmproxy] Errore fatale: http_split non è un JSON valido: {value}")
                        return

                num_chunks = int(value.get("chunks", 5))

                body = flow.request.raw_content
                print(f"body raw: {body}")
                body = flow.request.get_text()
                print(f"body: {body}")
                
                if not body:
                    return

                chunk_size = math.ceil(len(body) / num_chunks)
                print(f"chunk size: {chunk_size}")

                chunks = []
                for i in range(0, len(body), chunk_size):
                    chunks.append(body[i:i + chunk_size])
                print(f"chunks: {chunks}")

                # Ricostruisci il corpo nel formato chunked:
                # Ogni chunk deve essere: [lunghezza_esadecimale]\r\n[dati]\r\n
                chunked_body = b""
                for chunk in chunks:
                    chunk_bytes = chunk.encode('utf-8')
                    #chunked_body += f"{len(chunk_bytes):X}\r\n".encode('utf-8')
                    #chunked_body += chunk_bytes + b"\r\n"
                    chunked_body += f"{len(chunk_bytes):X}\r\n".encode('utf-8') + chunk_bytes + b"\r\n"
                # Aggiungi il blocco di chiusura (0\r\n\r\n)
                chunked_body += b"0\r\n\r\n"
                print(f"Chuncked body: {chunked_body}")

                # Ora assegna il corpo al flusso
                print(f"Flow_request_content before: {flow.request.content}")
                #flow.request.content = chunked_body
                flow.request.raw_content = chunked_body
                print(f"Flow_request_content after: {flow.request.content}")
      
                # abilita chunked transfer
                flow.request.headers["Transfer-Encoding"] = "chunked"
                if "Content-Length" in flow.request.headers:
                    del flow.request.headers["Content-Length"]

                """
                new_body = b""
                for chunk in chunks:
                    #time.sleep(delay_ms / 1000)
                    chunk_len = hex(len(chunk))[2:].encode()
                    new_body += chunk_len + b"\r\n"
                    new_body += chunk + b"\r\n"

                new_body += b"0\r\n\r\n"
                flow.request.raw_content = new_body

                print(f"[Mitmproxy] HTTP split applicato | chunks={len(chunks)} | chunk_size={chunk_size}")"""
            
            # -------------------------------------------------
            #  HTTP SPLIT -> MULTIPLE REQUESTS
            # -------------------------------------------------
            if "http_split_old" in mutations:
                value = mutations["http_split"]

                if isinstance(value, str):
                    try:
                        value = json.loads(value)
                    except json.JSONDecodeError:
                        print(f"[Mitmproxy] Errore fatale: http_split non è un JSON valido: {value}")
                        return

                num_chunks = int(value.get("chunks", 5))

                body = flow.request.content
                if not body:
                    return

                #chunk_size = max(1, len(body) // num_chunks)
                chunk_size = math.ceil(len(body) / num_chunks)

                chunks = [
                    body[i:i + chunk_size]
                    for i in range(0, len(body), chunk_size)
                ]

                print(f"[Mitmproxy] HTTP split -> Generazione {len(chunks)} richieste | chunk_size={chunk_size}")
                    
                # interrompe request originale
                flow.kill()

                # genera N request indipendenti
                for i, chunk in enumerate(chunks):
                    new_flow = flow.copy()

                    new_flow.request.content = chunk

                    new_flow.request.headers["Content-Length"] = str(len(chunk))

                    # opzionale: traccia ordine
                    # Aggiungi header di controllo per evitare loop e tracciare l'ordine
                    new_flow.request.headers["X-Is-Replayed"] = "true"
                    new_flow.request.headers["X-Chunk-Index"] = str(i)
                    new_flow.request.headers["X-Total-Chunks"] = str(len(chunks))

                    # rimuovi length (mitmproxy lo rigenera)
                    # new_flow.request.headers.pop("Content-Length", None)

                    ctx.master.commands.call(
                        "replay.client",
                        [new_flow]
                    )

        except Exception as e:
            print(f"[Mitmproxy] Errore: {e}")

addons = [EvasionAddon()]