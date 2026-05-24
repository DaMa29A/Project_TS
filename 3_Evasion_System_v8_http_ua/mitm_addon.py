# mitm_addon.py
import json
from pathlib import Path
from mitmproxy import http

SHARED_FILE = Path("current_l7_mutation.json")

class EvasionAddon:
    def request(self, flow: http.HTTPFlow):
        # Controlliamo se esiste una mutazione attiva decisa dall'LLM
        if SHARED_FILE.exists():
            try:
                with open(SHARED_FILE, "r") as f:
                    mutation = json.load(f)
                
                # Se la strategia è di mutare l'User-Agent, lo cambiamo al volo
                if mutation.get("field_to_mutate") == "user_agent":
                    new_ua = str(mutation.get("new_value"))
                    flow.request.headers["User-Agent"] = new_ua
                    print(f"[Mitmproxy] 🎭 User-Agent mutato in: {new_ua[:30]}...")

            except Exception as e:
                print(f"[Mitmproxy] Errore nella lettura della mutazione: {e}")

# Registriamo l'add-on in mitmproxy
addons = [EvasionAddon()]