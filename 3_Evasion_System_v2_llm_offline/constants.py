from pathlib import Path

# --- PATH ---
BASE_DIR = Path(__file__).resolve().parent.parent
INPUT_DIR = BASE_DIR / "input"
OUTPUT_DIR = BASE_DIR / "output"
BASELINE_JSON = INPUT_DIR / "baseline_stats.json"

# ---  OLLAMA API ---
# OLLAMA_IP = "192.168.98.1"    # KALI
OLLAMA_IP = "127.0.0.1"         # WIN
OLLAMA_PORT = "11434"
OLLAMA_BASE_URL = f"http://{OLLAMA_IP}:{OLLAMA_PORT}"
OLLAMA_URL = f"{OLLAMA_BASE_URL}/api/generate"

# ---  OLLAMA MODELS ---
OLLAMA_MODEL = "llama3.1:8b"
# OLLAMA_MODEL = "llama3.2:3b"