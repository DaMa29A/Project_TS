import sys
import time
import random
from scapy.all import conf
from models import MutationStrategy
from protocol_mutator import craft_mutated_packet
from traffic_emitter import emit_packet             # Modulo 4
from feedback_analyzer import FeedbackAnalyzer      # Modulo 5

# Disabilita i messaggi prolissi di Scapy a terminale
conf.verb = 0

# Configurazioni del Target di Test
TARGET_IP = "192.168.20.10"
TARGET_PORT = 80
NUM_TESTS = 50  # Numero di cicli di mutazione da eseguire

def get_dummy_strategy() -> MutationStrategy:
    """
    Simula l'LLM generando una mutazione casuale del TTL ad ogni chiamata.
    Questo trasforma il ciclo in un fuzzer per testare le risposte del firewall.
    """
    ttl_randomico = random.randint(1, 255)
    return MutationStrategy(
        field_to_mutate="ttl",
        new_value=ttl_randomico,
        reasoning=f"Test fuzzer del livello IP con TTL generato casualmente a {ttl_randomico}."
    )

def run_evasion_loop():
    print(f"=== Avvio Evasion System (Architettura Disaccoppiata) ===")
    print(f"[*] Bersaglio impostato: {TARGET_IP}:{TARGET_PORT}")
    print(f"[*] Totale test pianificati: {NUM_TESTS}\n")
    
    # Contatori per le metriche di valutazione
    successi = 0
    fallimenti = 0
    timeout_count = 0

    # Inizializzazione del modulo Feedback Analyzer
    analyzer = FeedbackAnalyzer(target_ip=TARGET_IP, timeout=1.5)

    for i in range(1, NUM_TESTS + 1):
        print(f"--- Iterazione {i}/{NUM_TESTS} ---")
        
        # 1. Generazione della strategia di mutazione (Finto LLM Engine)
        strategy = get_dummy_strategy()
        print(f"[*] Mutazione applicata: '{strategy.field_to_mutate}' = {strategy.new_value}")
        
        # 2. Crafting del pacchetto di rete (Protocol Mutation Generator)
        mutated_pkt = craft_mutated_packet(TARGET_IP, TARGET_PORT, strategy)

        # 3. Attivazione dello Sniffer in background (Success Feedback Analyzer)
        analyzer.start_listening()
        
        # 4. Iniezione del pacchetto sulla rete (Traffic Emitter Module)
        emit_packet(mutated_pkt)

        # 5. Elaborazione del verdetto di rete (Success Feedback Analyzer)
        reward = analyzer.get_reward()
        
        # Aggiornamento delle statistiche in base al reward ricevuto
        if reward == 1:
            successi += 1
        elif reward == -1:
            # Se lo sniffer non ha collezionato pacchetti, si tratta di un drop silente
            if len(analyzer.sniffer.results) == 0:
                timeout_count += 1
            else:
                fallimenti += 1
            
        # Breve pausa (Jitter) prima della prossima iterazione per non saturare la coda di rete
        time.sleep(0.5)

    # Calcolo dell'Evasion Success Rate (Metrica di valutazione finale)
    evasion_success_rate = (successi / NUM_TESTS) * 100

    # Stampa del report statistico finale
    print("\n==================================================")
    print("      REPORT FINALE - EVALUATION METRICS")
    print("==================================================")
    print(f"Campo protocollo testato:  ttl (Valori casuali 1-255)")
    print(f"Totale pacchetti inviati:  {NUM_TESTS}")
    print(f"Evasion Success Rate:      {evasion_success_rate:.1f}%")
    print(f" -> Connessioni Riuscite (SYN-ACK): {successi}")
    print(f" -> Blocchi Rilevati (RST/ICMP):   {fallimenti}")
    print(f" -> Drop Silenti (Timeout):         {timeout_count}")
    print("==================================================")

if __name__ == "__main__":
    try:
        run_evasion_loop()
    except KeyboardInterrupt:
        print("\n[!] Ciclo chiuso interrotto dall'operatore.")
        sys.exit(0)