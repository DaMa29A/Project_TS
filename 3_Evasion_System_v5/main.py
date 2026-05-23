import time
from scapy.all import conf, TCP, IP
from llm_strategy_engine import LLMEvasionStrategyEngine
from constants import BASELINE_JSON, OLLAMA_MODEL, OLLAMA_BASE_URL
from models import NetworkFeedback, PacketState
from rl_classifier import RLMutationClassifier
from feedback_analyzer import FeedbackAnalyzer
from traffic_emitter import emit_packet
from protocol_mutator import create_baseline_packet, apply_mutation
from utils import load_json

# --- CONFIGURAZIONI ---
conf.verb = 0

TARGET_IP = "192.168.20.10"
TARGET_PORT = 80
MAX_ATTEMPTS = 10


def main():
    print("--- Inizializzazione LLM Evasion Engine ---")
    try:
        engine = LLMEvasionStrategyEngine(
            ollama_url=OLLAMA_BASE_URL, #OLLAMA_URL
            model=OLLAMA_MODEL
        )

        baseline=load_json(BASELINE_JSON)

        clf = RLMutationClassifier(min_samples_to_train=5)
        clf.load_state()

        last_feedback = None

        pk = create_baseline_packet(TARGET_IP, TARGET_PORT)
        p_state = PacketState(ttl=pk[IP].ttl, win_size=pk[TCP].window, seq_num=pk[TCP].seq, flags=str(pk[TCP].flags))

        # --- METRICS ---
        success_count = 0
        latencies = []

        i = 0 
        while i < MAX_ATTEMPTS:
            print(f"--- TEST {i + 1} ---")
            
            # 1. Misurazione Latenza Inizio
            start_time = time.time()

            strategy = engine.generate_strategy(baseline=baseline, last_feedback=last_feedback)

            # 2. Misurazione Latenza Fine
            end_time = time.time()
            latency = end_time - start_time
            latencies.append(latency)

            print("Generated Strategy:", strategy)
            print(f"Latenza LLM: {latency:.2f} secondi")
            
            match strategy.field_to_mutate:
                case "ttl":
                    p_state.ttl = strategy.new_value
                case "win_size":
                    p_state.win_size = strategy.new_value
                case "seq_num":
                    p_state.seq_num = strategy.new_value
                case "flags":
                    p_state.flags = strategy.new_value
                case _: # 'default'
                    pass
            
            prob = clf.predict_success_probability(p_state)
            print(f"Probability of Success: {prob * 100:.0f}%")


            # --------- PROTOCOL MUTATOR ---------
            mutated_pkt = apply_mutation(base_packet=pk, strategy=strategy)
            # Estraiamo la source port appena generata per dire allo sniffer cosa ascoltare
            current_sport = mutated_pkt[TCP].sport

            # --------- FEEDBACK ANALYZER ---------
            analyzer = FeedbackAnalyzer(target_ip=TARGET_IP, sport=current_sport, timeout=2.5)
            analyzer.start_listening()
            time.sleep(0.1) # Diamo il tempo allo sniffer di avviarsi

            # --------- TRAFFIC EMITTER ---------
            emit_packet(mutated_pkt)

            # Raccolta dati
            reward = analyzer.get_reward()

            if reward == 1:
                verdict = "PASS"
                reason = "Strategy successfully evaded the firewall rules. [(SYN-ACK)]"
                success_count += 1
                pk = mutated_pkt.copy()
            elif reward == -1:
                verdict = "BLOCK"
                if len(analyzer.sniffer.results) == 0:
                    reason = "Strategy failed to evade the firewall rules. [Drop Silenti (Timeout)]"
                else:
                    reason = "Strategy failed to evade the firewall rules. [(RST/ICMP)]"
 
            # Ritardo tra iterazioni per evitare ban/rate-limiting del firewall
            # time.sleep(5.0)


            print(f"Feedback: {verdict} -> {reward}")
            clf.add_experience(p_state, reward)

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
        clf.save_state()

        # --- CALCOLO E STAMPA METRICHE FINALI ---
        avg_latency = sum(latencies) / len(latencies) if latencies else 0
        evasion_rate = (success_count / MAX_ATTEMPTS) * 100
        
        print("=" * 50)
        print("📊 REPORT FINALE DELLA SESSIONE")
        print("=" * 50)
        print(f"Evasion Success Rate : {evasion_rate:.1f}% ({success_count} successi su {MAX_ATTEMPTS} tentativi)")
        print(f"Latenza Media LLM    : {avg_latency:.2f} secondi per iterazione")
        print(f"Stato RL Globale     : {clf.get_memory_stats()}")
        print("=" * 50)

    except Exception as e:
        print(f"Errore durante l'inizializzazione dell'engine: {e}")
        return

if __name__ == "__main__":
    main()