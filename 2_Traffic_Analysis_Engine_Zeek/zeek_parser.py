import json
from pathlib import Path
from utils import safe_numeric_stats, top_frequencies, calculate_entropy
from constants import ZEEK_DIR

def parse_zeek_json_log(filepath, key_to_extract):
    """Legge un log Zeek in formato JSON e ne estrae una specifica chiave."""
    values = []
    
    path_obj = Path(filepath)
    
    if not path_obj.exists():
        print(f"[!] Log Zeek non trovato: {path_obj}") 
        return values
        
    with open(path_obj, 'r', encoding='utf-8') as f:
        for line in f:
            try:
                data = json.loads(line.strip())
                if key_to_extract in data:
                    values.append(data[key_to_extract])
            except json.JSONDecodeError:
                continue
    return values

def get_zeek_http():
    http_log = ZEEK_DIR / "http.log"
    
    # HTTP (da http.log)
    methods = parse_zeek_json_log(http_log, "method")
    user_agents = parse_zeek_json_log(http_log, "user_agent")

    return {
        "http": {
            "methods": {"top_values": top_frequencies(methods)},
            "user_agents": {
                "top_values": top_frequencies(user_agents),
                "entropy": calculate_entropy(user_agents)
            }
        }
    }


def get_zeek_flow():
    conn_log = ZEEK_DIR / "conn.log"

    # FLOW PROFILING (da conn.log)
    durations = parse_zeek_json_log(conn_log, "duration")
    orig_pkts = parse_zeek_json_log(conn_log, "orig_pkts")
    orig_bytes = parse_zeek_json_log(conn_log, "orig_ip_bytes")
    
    return {
        "flow_profiling": {
            "total_flows": len(durations),
            "flow_duration": safe_numeric_stats(durations),
            "packets_per_flow": safe_numeric_stats(orig_pkts),
            "bytes_per_flow": safe_numeric_stats(orig_bytes)
        }
    }


def get_zeek_tls():
    ssl_log = ZEEK_DIR / "ssl.log"

    # TLS (da ssl.log)
    ciphersuites = parse_zeek_json_log(ssl_log, "cipher")
    
    return {
        "tls_ciphersuites": {
            "top_values": top_frequencies(ciphersuites),
            "entropy": calculate_entropy(ciphersuites)
        }
    }