from rl_classifier import RLMutationClassifier
from models import PacketState

def run_test():
    print("=" * 60)
    print("🚀 AVVIO SCRIPT DI PREDIZIONE - CLASSIFICATORE RL (FULL-STATE)")
    print("=" * 60)

    # ---------------- FASE DI LOADING ----------------
    print("[Step 1] Fase di Loading dello stato salvato...")
    nuovo_clf = RLMutationClassifier()
    print(f"- Stato del nuovo classificatore (prima del load): \n{nuovo_clf.get_memory_stats()}")
    
    nuovo_clf.load_state()
    print(f"- Stato del nuovo classificatore (dopo il load): \n{nuovo_clf.get_memory_stats()}")

    # ---------------- FASE DI PREDIZIONE ----------------
    print("\n" + "-"*50)
    print("[Step 2] Fase di Predizione Oracolo")
    print("-"*50)
    
    # Chiediamo al Random Forest di stimare la probabilità
    test_cases = [
        {"desc": "TTL=64, standard", "state": PacketState(ttl=64, win_size=126, seq_num=1000, flags="S")},
        {"desc": "TTL=150, moderatamente anomalo", "state": PacketState(ttl=150, win_size=126, seq_num=1000, flags="S")},
        {"desc": "TTL=255, anomalo", "state": PacketState(ttl=255, win_size=126, seq_num=1000, flags="S")},
        {"desc": "Flags=S, standard", "state": PacketState(ttl=64, win_size=126, seq_num=1000, flags="S")},
        {"desc": "Flags=FPU, XMAS scan", "state": PacketState(ttl=64, win_size=126, seq_num=1000, flags="FPU")},
        {"desc": "WinSize=506", "state": PacketState(ttl=64, win_size=506, seq_num=1000, flags="S")},
        {"desc": "WinSize=999, mai visto", "state": PacketState(ttl=64, win_size=999, seq_num=1000, flags="S")},
        {"desc": "COMBINAZIONE LETALE (TTL=255 + FPU)", "state": PacketState(ttl=255, win_size=126, seq_num=1000, flags="FPU")}
    ]
    
    for case in test_cases:
        # Passiamo direttamente l'oggetto PacketState al metodo predict
        prob = nuovo_clf.predict_success_probability(case["state"])
        print(f"   * Stima per [{case['desc']}] : {prob * 100:.0f}%")

if __name__ == "__main__":
    run_test()