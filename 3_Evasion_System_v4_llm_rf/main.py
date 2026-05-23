import random
from llm_strategy_engine import LLMEvasionStrategyEngine
from constants import BASELINE_JSON, OLLAMA_MODEL, OLLAMA_BASE_URL
from models import NetworkFeedback, PacketState
from rl_classifier import RLMutationClassifier
from utils import load_json

# --- CONFIGURAZIONI ---
MAX_ATTEMPTS = 2


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
        p_state = PacketState(ttl=0, win_size=0, seq_num=0, flags="")

        i = 0 
        while i < MAX_ATTEMPTS:
            print(f"--- TEST {i + 1} ---")
            
            strategy = engine.generate_strategy(baseline=baseline, last_feedback=last_feedback)
            print("Generated Strategy:", strategy)
            
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

            fake_reward = random.choice([-1, 1])
            if fake_reward == 1:
                fake_verdict = "PASS"
                fake_reason = "Strategy successfully evaded the firewall rules."
            elif fake_reward == -1:
                fake_verdict = "BLOCK"
                fake_reason = "Strategy failed to evade the firewall rules."
            
            print(f"Feedback: {fake_verdict} - {fake_reward}")
            clf.add_experience(p_state, fake_reward)

            last_feedback = NetworkFeedback(
                verdict=fake_verdict,
                reward=fake_reward,
                reason=fake_reason,
                field_tested=strategy.field_to_mutate,
                value_tested=strategy.new_value
            ) 


            i += 1
            print(f"\n")
        
        # Salvataggio dello stato
        clf.save_state()

    except Exception as e:
        print(f"Errore durante l'inizializzazione dell'engine: {e}")
        return

if __name__ == "__main__":
    main()