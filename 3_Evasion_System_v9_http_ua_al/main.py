import json
import threading
import subprocess
import time
import os
import signal
from netfilterqueue import NetfilterQueue
from evasion_proxy import EvasionProxy
from constants import TARGET_IP
from models import MutationStrategy, PacketState

def orchestrator_loop(proxy):
    print("[Orchestratore] Attendo 1.5 secondi per l'avvio della coda NFQueue...")
    time.sleep(1.5) 
    
    # Simuliamo le strategie generate dall'LLM per i test
    strategie_di_test = [
        MutationStrategy(field_to_mutate="user_agent", new_value="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", reasoning="Test 1"),
        MutationStrategy(field_to_mutate="ttl", new_value=90, reasoning="Test 2"),
        MutationStrategy(field_to_mutate="accept_language", new_value="it-IT,it;q=0.9", reasoning="Test 3"),
        MutationStrategy(field_to_mutate="user_agent", new_value="PoE2-Discord-Bot/1.0.0", reasoning="Test 1"),
        MutationStrategy(field_to_mutate="win_size", new_value=666, reasoning="Test 4"),
    ]

    # --- LA NOSTRA CASSAFORTE DELLE MUTAZIONI FUNZIONANTI ---
    active_mutations = {}

    for i, strategia in enumerate(strategie_di_test):
        print(f"\n" + "="*50)
        print(f"--- TEST {i + 1} | LLM Tenta: {strategia.field_to_mutate} -> {strategia.new_value} ---")
        
        # 1. Creiamo lo stato DA TESTARE (Mutazioni Funzionanti Passate + Nuova Mutazione)
        test_state = active_mutations.copy()
        test_state[strategia.field_to_mutate] = strategia.new_value
        
        print(f"[Orchestratore] Stato Globale in test: {test_state}")

        # 2. GESTIONE L7 (Mitmproxy)
        l7_mutations = {}
        if "user_agent" in test_state: l7_mutations["user_agent"] = test_state["user_agent"]
        if "accept_language" in test_state: l7_mutations["accept_language"] = test_state["accept_language"]
        
        if l7_mutations:
            with open("current_l7_mutation.json", "w") as f:
                json.dump(l7_mutations, f)
        else:
            if os.path.exists("current_l7_mutation.json"):
                os.remove("current_l7_mutation.json")

        # 3. GESTIONE L3/L4 (Scapy / Evasion Proxy)
        proxy.flow_state = {} # Reset del tracking di connessione tra un test e l'altro
        proxy.p_state = PacketState() # Reset stato pacchetti base
        
        # Ricostruiamo il PacketState aggiornato
        if "ttl" in test_state: proxy.p_state.ttl = test_state["ttl"]
        if "win_size" in test_state: proxy.p_state.win_size = test_state["win_size"]
        if "seq_num" in test_state: proxy.p_state.seq_num = test_state["seq_num"]
        if "user_agent" in test_state: proxy.p_state.user_agent = str(test_state["user_agent"])
        if "accept_language" in test_state: proxy.p_state.accept_language = str(test_state["accept_language"])
        
        proxy.mutation = strategia # Impostiamo per i log in evasion_proxy.py
        
        # Invio traffico
        print(f"[Orchestratore] Lancio la richiesta HTTP verso {TARGET_IP}...")
        try:
            risultato = subprocess.run(
                ["curl", "-x", "http://127.0.0.1:8080", "-s", "--max-time", "3", f"http://{TARGET_IP}"], 
                capture_output=True, text=True
            )
            
            # 4. VALUTIAMO IL REWARD E AGGIORNIAMO LA CASSAFORTE
            if risultato.returncode == 0:
                print("[Orchestratore] [+] Risposta ricevuta dal Server! Evasione Riuscita! (Reward: +1)")
                reward = 1
                # Dato che ha funzionato, AGGIORNIAMO LA CASSAFORTE per il prossimo ciclo!
                active_mutations[strategia.field_to_mutate] = strategia.new_value
            else:
                print("[Orchestratore] [-] Nessuna risposta o blocco (Timeout). (Reward: -1)")
                reward = -1
                print(f"[*] La mutazione {strategia.field_to_mutate} verrà scartata dai prossimi test.")
                
            # Addestriamo il modello passandogli l'intero PacketState che abbiamo testato
            proxy.classifier.add_experience(proxy.p_state, reward)
        
        except Exception as e:
            print(f"[Orchestratore] Errore nell'invio: {e}")
            
        # Breve pausa prima del test successivo
        time.sleep(2)

    # Fine del ciclo. Diciamo al main thread di spegnersi simulando un Ctrl+C
    proxy.classifier.save_state()
    print("\n[Orchestratore] Tutti i test completati. Spengo l'Evasion Engine...")
    os.kill(os.getpid(), signal.SIGINT)


def main():
    proxy = EvasionProxy()

    # Prepariamo la coda (1) Nfqueue
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, proxy.manage_packet) # Ogni pacchetto che arriva sulla coda 1 viene gestito da proxy.manage_packet

    # Passiamo l'oggetto proxy come argomento all'altro thread
    trigger_thread = threading.Thread(target=orchestrator_loop, args=(proxy,))
    trigger_thread.start()
    
    # Avviamo l'ascolto sul thread principale
    try:
        print("[*] Evasion Engine V7 in attesa sulla coda 1...")
        nfqueue.run() # Questo blocca finché non arriva il segnale os.kill()
    except KeyboardInterrupt:
        print("\n[*] Chiusura forzata dell'engine completata con successo.")
    finally:
        nfqueue.unbind()

if __name__ == "__main__":
    main()