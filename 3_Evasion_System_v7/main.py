import threading
import subprocess
import time
import os
import signal
from netfilterqueue import NetfilterQueue
from evasion_proxy import EvasionProxy
from llm_strategy_engine import LLMEvasionStrategyEngine
from rl_classifier import RLMutationClassifier
from feedback_analyzer import FeedbackAnalyzer
from constants import TARGET_IP, OLLAMA_BASE_URL, OLLAMA_MODEL, BASELINE_JSON
from models import MutationStrategy, PacketState, NetworkFeedback
from utils import load_json, calculate_js_distance

MAX_ATTEMPTS = 10

def orchestrator_loop(proxy):
    print("[orchestrator_loop] Attendo 1.5 secondi per l'avvio della coda NFQueue...")
    time.sleep(1.5) 

    print("--- Inizializzazione LLM Evasion Engine ---")
    try:
        engine = LLMEvasionStrategyEngine(
            ollama_url=OLLAMA_BASE_URL, #OLLAMA_URL
            model=OLLAMA_MODEL
        )

        baseline=load_json(BASELINE_JSON)

        #clf = RLMutationClassifier(min_samples_to_train=5)
        #clf.load_state()

        last_feedback = None

        # p_state = PacketState(ttl=0, win_size=0, seq_num=0, flags="")

        # --- METRICS ---
        success_count = 0
        latencies = []

        # Dizionario per memorizzare i valori storici mutati per ogni campo
        applied_mutations = {
            "ttl": [],
            "win_size": [],
            "seq_num": []
        }

        i = 0 
        while i < MAX_ATTEMPTS:
            print(f"--- TEST {i + 1} ---")

            # 1. Misurazione Latenza Inizio
            start_time = time.time()

            strategy = engine.generate_strategy(baseline=baseline, last_feedback=last_feedback)

            # Registra il valore mutato per le metriche JSD
            if strategy.field_to_mutate in applied_mutations:
                applied_mutations[strategy.field_to_mutate].append(strategy.new_value)

            # 2. Misurazione Latenza Fine
            end_time = time.time()
            latency = end_time - start_time
            latencies.append(latency)

            print("Generated Strategy:", strategy)
            print(f"Latenza LLM: {latency:.2f} secondi")

            '''match strategy.field_to_mutate:
                case "ttl":
                    p_state.ttl = strategy.new_value
                case "win_size":
                    p_state.win_size = strategy.new_value
                case "seq_num":
                    p_state.seq_num = strategy.new_value
                case "flags":
                    p_state.flags = strategy.new_value
                case _: # 'default'
                    pass'''

            #prob = clf.predict_success_probability(p_state)
            #print(f"Probability of Success: {prob * 100:.0f}%")

            # Modifica strategia
            proxy.mutation = strategy
            print(f"[Orchestratore] Impostata strategia: Muta {strategy.field_to_mutate} in {strategy.new_value}")

            # --------- FEEDBACK ANALYZER ---------
            analyzer = FeedbackAnalyzer(target_ip=TARGET_IP, sport=None, timeout=3.5)
            analyzer.start_listening()
            time.sleep(0.2) # Diamo il tempo allo sniffer di avviarsi

            # Invio traffico
            print(f"[Orchestratore] Lancio la richiesta HTTP verso {TARGET_IP}...")
            risultato = subprocess.run(
                ["curl", "-s", "--max-time", "3", f"http://{TARGET_IP}"], 
                capture_output=True, text=True
            )

            # --- VALUTIAMO IL REWARD TRAMITE LO SNIFFER REALE ---
            reward, verdict, reason = analyzer.get_reward()

            if reward == 1:
                success_count += 1
            elif reward == -1:
                pass

            print(f"Feedback: {verdict} -> {reward}")
            proxy.classifier.add_experience(proxy.p_state, reward)

            last_feedback = NetworkFeedback(
                verdict=verdict,
                reward=reward,
                reason=reason,
                field_tested=strategy.field_to_mutate,
                value_tested=strategy.new_value
            ) 

            i += 1
            print(f"\n")
            
        # Salvataggio dello stato
        proxy.classifier.save_state()

        # --- CALCOLO E STAMPA METRICHE FINALI ---
        avg_latency = sum(latencies) / len(latencies) if latencies else 0
        evasion_rate = (success_count / MAX_ATTEMPTS) * 100
        
        # Calcolo Mutation Stealth (JSD) per i campi principali
        js_distances = {}
        if baseline and "features" in baseline:
            # Esempio per TTL
            ttl_baseline = baseline["features"]["ttl"].get("top_values", [])
            js_distances["ttl"] = calculate_js_distance(ttl_baseline, applied_mutations["ttl"])
            
            # Esempio per TCP Window Size
            win_baseline = baseline["features"]["tcp"]["window_size"].get("top_values", [])
            js_distances["win_size"] = calculate_js_distance(win_baseline, applied_mutations["win_size"])

            # Esempio per Sequence Number
            seq_baseline = baseline["features"]["tcp"]["seq_num"].get("top_values", [])
            js_distances["seq_num"] = calculate_js_distance(seq_baseline, applied_mutations["seq_num"])


        print("=" * 50)
        print("📊 REPORT FINALE DELLA SESSIONE")
        print("=" * 50)
        print(f"Evasion Success Rate : {evasion_rate:.1f}% ({success_count} successi su {MAX_ATTEMPTS} tentativi)")
        print(f"Latenza Media LLM    : {avg_latency:.2f} secondi per iterazione")
        print(f"Stato RL Globale     : {proxy.classifier.get_memory_stats()}")
        print("Mutation Stealth (JSD) [0.0 = Invisibile, 1.0 = Anomalo]:")
        for field, dist in js_distances.items():
            print(f"  - {field.upper()}: {dist:.4f}")
        print("=" * 50)

        # Fine del ciclo. Diciamo al main thread di spegnersi simulando un Ctrl+C
        print("\n[Orchestratore] Tutti i test completati. Spengo l'Evasion Engine...")
        os.kill(os.getpid(), signal.SIGINT)

    except Exception as e:
        print(f"[Orchestratore] Errore : {e}")


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
        print("[*] Evasion Engine in attesa sulla coda 1...")
        nfqueue.run() # Questo blocca finché non arriva il segnale os.kill()
    except KeyboardInterrupt:
        print("\n[*] Chiusura forzata dell'engine completata con successo.")
    finally:
        nfqueue.unbind()

if __name__ == "__main__":
    main()