import json
import threading
import subprocess
import time
import os
import signal
from netfilterqueue import NetfilterQueue
from evasion_proxy import EvasionProxy
from constants import TARGET_IP
from models import MutationStrategy

# sudo iptables -A OUTPUT -p tcp -d 192.168.20.10 --dport 80 -j NFQUEUE --queue-num 1

def orchestrator_loop(proxy):
    print("[Orchestratore] Attendo 1.5 secondi per l'avvio della coda NFQueue...")
    time.sleep(1.5) 
    
    # Simuliamo due strategie generate dall'LLM per questo test
    strategie_di_test = [
        MutationStrategy(field_to_mutate="user_agent", new_value="Morilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", reasoning="Test 1"),
        MutationStrategy(field_to_mutate="win_size", new_value=90, reasoning="Test 2")
    ]
    ua_state = None

    for i, strategia in enumerate(strategie_di_test):
        print(f"\n" + "="*40)
        print(f"--- TEST {i + 1} ---")

        if strategia.field_to_mutate == "user_agent":   
            ua_state = strategia.new_value
        
        if ua_state:
            print(f"[Orchestratore] Stato User-Agent attuale: {ua_state}")
            with open("current_l7_mutation.json", "w") as f:
                json.dump({"field_to_mutate": "user_agent", "new_value": ua_state}, f)
                
        # Modifica strategia
        proxy.mutation = strategia
        print(f"[Orchestratore] Impostata strategia: Muta {strategia.field_to_mutate} in {strategia.new_value}")
        
        # Invio traffico
        print(f"[Orchestratore] Lancio la richiesta HTTP verso {TARGET_IP}...")
        try:
            risultato = subprocess.run(
                ["curl", "-x", "http://127.0.0.1:8080", "-s", "--max-time", "3", f"http://{TARGET_IP}"], 
                capture_output=True, text=True
            )
            # 3. VALUTIAMO IL REWARD
            if risultato.returncode == 0:
                print("[Orchestratore] [+] Risposta ricevuta dal Server! Evasione Riuscita! (Reward: +1)")
            else:
                print("[Orchestratore] [-] Nessuna risposta o blocco (Timeout). (Reward: -1)")
        
        except Exception as e:
            print(f"[Orchestratore] Errore nell'invio: {e}")
            
        # Breve pausa prima del test successivo
        time.sleep(2)

    # Fine del ciclo. Diciamo al main thread di spegnersi simulando un Ctrl+C
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
        print("[*] Evasion Engine V6 in attesa sulla coda 1...")
        nfqueue.run() # Questo blocca finché non arriva il segnale os.kill()
    except KeyboardInterrupt:
        print("\n[*] Chiusura forzata dell'engine completata con successo.")
    finally:
        nfqueue.unbind()

if __name__ == "__main__":
    main()