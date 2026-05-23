from rl_classifier import RLMutationClassifier
from models import PacketState

def run_test():
    print("=" * 60)
    print("🚀 AVVIO SCRIPT DI TRAINING - CLASSIFICATORE RL")
    print("=" * 60)
    
    # Inizializziamo il classificatore (minimo 5 campioni per avviare il fitting)
    clf = RLMutationClassifier(min_samples_to_train=5)
    
    # Dataset fittizio: simuliamo pacchetti interi.
    mock_history = [
        # COMPORTAMENTO TTL
        {"state": PacketState(ttl=64, win_size=126, seq_num=1000, flags="S"), "reward": 1},
        {"state": PacketState(ttl=63, win_size=126, seq_num=1000, flags="S"), "reward": 1},
        {"state": PacketState(ttl=128, win_size=126, seq_num=1000, flags="S"), "reward": -1},
        {"state": PacketState(ttl=255, win_size=126, seq_num=1000, flags="S"), "reward": -1},
        
        # COMPORTAMENTO FLAGS
        {"state": PacketState(ttl=64, win_size=126, seq_num=1000, flags="S"), "reward": 1},
        {"state": PacketState(ttl=64, win_size=126, seq_num=1000, flags="FPU"), "reward": -1},
        {"state": PacketState(ttl=64, win_size=126, seq_num=1000, flags="SF"), "reward": -1},
        {"state": PacketState(ttl=64, win_size=126, seq_num=1000, flags="A"), "reward": -1},
        
        # COMPORTAMENTO WINDOW SIZE
        {"state": PacketState(ttl=64, win_size=126, seq_num=1000, flags="S"), "reward": 1},
        {"state": PacketState(ttl=64, win_size=506, seq_num=1000, flags="S"), "reward": 1},
    ]
    
    # ---------------- FASE ADDESTRAMENTO PROGRESSIVO ----------------
    print("\n[Step 1] Caricamento progressivo della cronologia nel modello...")
    for i, entry in enumerate(mock_history):
        # Passiamo direttamente l'oggetto PacketState e il reward
        clf.add_experience(entry["state"], entry["reward"])
        
        if clf.is_trained:
            print(f"   -> [Campione {i+1:02d}] Modello addestrato! {clf.get_memory_stats()}")
        else:
            print(f"   -> [Campione {i+1:02d}] Accumulo dati... Modello non ancora addestrato (Soglia < 5).")
    
    # Salvataggio dello stato
    clf.save_state()
    
if __name__ == "__main__":
    run_test()