import sys
import time
import random
from scapy.all import conf, TCP
from models import MutationStrategy
from protocol_mutator import craft_mutated_packet
from traffic_emitter import emit_packet
from feedback_analyzer import FeedbackAnalyzer

conf.verb = 0

TARGET_IP = "192.168.20.10"
TARGET_PORT = 80
NUM_TESTS = 50

def get_ttl_strategy() -> MutationStrategy:
    ttl_randomico = random.randint(1, 255)
    return MutationStrategy(
        field_to_mutate="ttl",
        new_value=ttl_randomico,
        reasoning=f"Test fuzzer del livello IP con TTL generato casualmente a {ttl_randomico}."
    )

def get_winsize_strategy() -> MutationStrategy:
    """Simula l'LLM generando una mutazione casuale della TCP Window Size."""
    # Generiamo una Window Size casuale tra 0 e 65535 (limite del campo TCP a 16 bit)
    win_randomico = random.randint(0, 65535)
    return MutationStrategy(
        field_to_mutate="win_size",
        new_value=win_randomico,
        reasoning=f"Test fuzzer del livello TCP con Window Size generata casualmente a {win_randomico}."
    )

def get_seqnum_strategy() -> MutationStrategy:
    """Simula l'LLM generando una mutazione casuale del Sequence Number."""
    # I Sequence Number TCP sono a 32 bit, quindi vanno da 0 a 4.294.967.295
    seq_randomico = random.randint(0, 2**32 - 1)
    
    return MutationStrategy(
        field_to_mutate="seq_num",
        new_value=seq_randomico,
        reasoning=f"Test fuzzer del livello TCP con Seq Number generato casualmente a {seq_randomico}."
    )

def get_flag_strategy() -> MutationStrategy:
    """Simula l'LLM pescando combinazioni anomale di TCP Flags."""
    
    # Lista delle tecniche di evasione più famose:
    # "S" (SYN classico), "" (NULL Scan), "F" (FIN Scan), 
    # "FPU" (XMAS Scan), "SF" (SYN-FIN anomalo, molto illegale per il protocollo TCP),
    # "SA" (SYN-ACK fuori stato), "A" (ACK Scan per mappare regole firewall)
    # "R" non c'è perchè non riceve mai risposta
    flag_list = ["S", "", "F", "P", "U", "FPU", "SF", "SA", "A"]
    
    flag_randomico = random.choice(flag_list)
    
    return MutationStrategy(
        field_to_mutate="flags",
        new_value=flag_randomico,
        reasoning=f"Test fuzzer del livello TCP testando la combinazione di flag [{flag_randomico}]."
    )

def run_evasion_loop():
    print("=== Avvio Evasion System ===")
    
    successi = 0
    fallimenti = 0
    timeout_count = 0

    for i in range(1, NUM_TESTS + 1):
        print(f"\n--- Iterazione {i}/{NUM_TESTS} ---")
        
        # 1. Generazione strategia
        #strategy = get_ttl_strategy()
        #strategy = get_winsize_strategy()
        #strategy = get_seqnum_strategy()
        strategy = get_flag_strategy()
        
        # 2. Crafting (ora genera una source port randomica)
        mutated_pkt = craft_mutated_packet(TARGET_IP, TARGET_PORT, strategy)
        
        # Estraiamo la source port appena generata per dire allo sniffer cosa ascoltare
        current_sport = mutated_pkt[TCP].sport

        # 3. Inizializziamo e avviamo lo sniffer con la porta corretta
        analyzer = FeedbackAnalyzer(target_ip=TARGET_IP, sport=current_sport, timeout=2.5)
        analyzer.start_listening()
        
        # [FIX CRITICO] Diamo il tempo allo sniffer (interfaccia BPF) di avviarsi
        time.sleep(0.1)
        
        # 4. Invio pacchetto
        emit_packet(mutated_pkt)

        # 5. Raccolta dati
        reward = analyzer.get_reward()
        
        if reward == 1:
            successi += 1
        elif reward == -1:
            if len(analyzer.sniffer.results) == 0:
                timeout_count += 1
            else:
                fallimenti += 1
            
        # [FIX CRITICO] Ritardo tra iterazioni per evitare ban/rate-limiting del firewall
        time.sleep(5.0)

    # Stampa del report finale
    print("\n==================================================")
    print("      REPORT FINALE - EVALUATION METRICS")
    print("==================================================")
    #print(f"Campo protocollo testato:  ttl (Valori casuali 1-255)")
    #print(f"Campo protocollo testato:  win_size (Valori casuali 0-65535)")
    #print(f"Campo protocollo testato:  seq_num (Valori casuali 0 - 4.2B)")
    #print(f"Campo protocollo testato:  flags (NULL, FIN, XMAS, SYN-FIN, ecc.)")
    print(f"Totale pacchetti inviati:  {NUM_TESTS}")
    print(f"Evasion Success Rate:      {(successi/NUM_TESTS)*100:.1f}%")
    print(f" -> Connessioni Riuscite (SYN-ACK): {successi}")
    print(f" -> Blocchi Rilevati (RST/ICMP):   {fallimenti}")
    print(f" -> Drop Silenti (Timeout):         {timeout_count}")
    print("==================================================")

if __name__ == "__main__":
    run_evasion_loop()