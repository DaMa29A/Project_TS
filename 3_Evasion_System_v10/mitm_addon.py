import json
from pathlib import Path
from mitmproxy import http

SHARED_FILE = Path("current_l7_mutation.json")

class EvasionAddon:
    def request(self, flow: http.HTTPFlow):
        # Controlliamo se esiste una mutazione attiva decisa dall'Orchestratore
        if SHARED_FILE.exists():
            try:
                with open(SHARED_FILE, "r") as f:
                    mutations = json.load(f)
                
                # Applica User-Agent se presente nel dizionario
                if "user_agent" in mutations:
                    new_ua = str(mutations["user_agent"])
                    flow.request.headers["User-Agent"] = new_ua
                    print(f"[Mitmproxy] User-Agent mutato in: {new_ua[:30]}...")

                # Applica Accept-Language se presente nel dizionario
                if "accept_language" in mutations:
                    new_al = str(mutations["accept_language"])
                    flow.request.headers["Accept-Language"] = new_al
                    print(f"[Mitmproxy] Accept-Language mutato in: {new_al}")

            except Exception as e:
                print(f"[Mitmproxy] Errore nella lettura della mutazione: {e}")

# Registriamo l'add-on in mitmproxy
addons = [EvasionAddon()]