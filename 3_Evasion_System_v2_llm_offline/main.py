import random
from llm_strategy_engine import LLMEvasionStrategyEngine
from constants import BASELINE_JSON, OLLAMA_MODEL, OLLAMA_BASE_URL
from models import NetworkFeedback
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

        last_feedback = None

        i = 0 
        while i < MAX_ATTEMPTS:
            print(f"--- TEST {i + 1} ---")
            
            strategy = engine.generate_strategy(baseline=baseline, last_feedback=last_feedback)
            print("Generated Strategy:", strategy)

            fake_reward = random.choice([-1, 1])
            if fake_reward == 1:
                fake_verdict = "PASS"
                fake_reason = "Strategy successfully evaded the firewall rules."
            elif fake_reward == -1:
                fake_verdict = "BLOCK"
                fake_reason = "Strategy failed to evade the firewall rules."

            last_feedback = NetworkFeedback(
                verdict=fake_verdict,
                reward=fake_reward,
                reason=fake_reason,
                field_tested=strategy.field_to_mutate,
                value_tested=strategy.new_value
            ) 

            i += 1
            print(f"\n")

    except Exception as e:
        print(f"Errore durante l'inizializzazione dell'engine: {e}")
        return

if __name__ == "__main__":
    main()