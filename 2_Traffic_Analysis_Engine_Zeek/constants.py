from pathlib import Path

# cartella root del modulo (2_Traffic_Analysis_Engine)
BASE_DIR = Path(__file__).resolve().parent

INPUT_DIR = BASE_DIR / "input"
OUTPUT_DIR = BASE_DIR / "output"

INPUT_PCAP = INPUT_DIR / "capture.pcap"
OUTPUT_JSON = OUTPUT_DIR / "baseline_stats.json"

#INPUT_PCAP = INPUT_DIR / "capture_mutated.pcap"
#OUTPUT_JSON = OUTPUT_DIR / "baseline_stats_mut.json"