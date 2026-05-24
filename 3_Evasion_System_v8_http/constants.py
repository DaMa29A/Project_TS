from pathlib import Path

# --- PATH ---
BASE_DIR = Path(__file__).resolve().parent
INPUT_DIR = BASE_DIR / "input"
OUTPUT_DIR = BASE_DIR / "output"
RL_DIR = BASE_DIR / "rl"
BASELINE_JSON = INPUT_DIR / "baseline_stats.json"
BASELINE_JSON_MUT = INPUT_DIR / "baseline_stats_mut.json"
RL_MEMORY = RL_DIR / "rl_memory.joblib"

# ---  OLLAMA API ---
OLLAMA_IP = "192.168.174.1"    # KALI
# OLLAMA_IP = "127.0.0.1"         # WIN
OLLAMA_PORT = "11434"
OLLAMA_BASE_URL = f"http://{OLLAMA_IP}:{OLLAMA_PORT}"
OLLAMA_URL = f"{OLLAMA_BASE_URL}/api/generate"

# ---  OLLAMA MODELS ---
# OLLAMA_MODEL = "llama3.1"
# OLLAMA_MODEL = "llama3.1:8b"
OLLAMA_MODEL = "llama3.2:3b"

# ---  IP ---
TARGET_IP = "192.168.20.10"