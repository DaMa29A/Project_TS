import json
import sys
from pathlib import Path
from scapy.all import rdpcap, IP, TCP
from scapy.layers.http import HTTPRequest
from constants import INPUT_PCAP, OUTPUT_JSON
from utils import safe_numeric_stats, top_frequencies, calculate_entropy

def analyze_pcap(pcap_path):
    packets = rdpcap(str(pcap_path)) # Caricamento dei pacchetti dal file pcap

    packet_sizes = []
    ttl_values = []
    ip_id_values = []  
    tcp_window_sizes = []
    inter_arrival_times = []
    tcp_flags = []
    tcp_options = []
    tcp_seq_numbers = []
    http_user_agents = []
    http_accept_languages = []
    http_methods = []

    last_time = None 
    error_printed = False

    # Estrazione delle caratteristiche dai pacchetti
    for pkt in packets:
        try:
            # 1. Packet Size
            packet_sizes.append(len(pkt))

            # 2. Inter-packet timing
            if hasattr(pkt, 'time') and pkt.time is not None:
                current_time = float(pkt.time)
                if last_time is not None:
                    diff = round(current_time - last_time, 6)
                    inter_arrival_times.append(diff)
                last_time = current_time

            # 3. Livello IP
            if IP in pkt:                   
                ttl_values.append(int(pkt[IP].ttl)) 
                ip_id_values.append(int(pkt[IP].id))  # Estrazione campo IP ID

            # 4. Livello TCP
            if TCP in pkt:                  
                tcp_window_sizes.append(int(pkt[TCP].window)) 
                tcp_seq_numbers.append(int(pkt[TCP].seq))
                tcp_flags.append(str(pkt[TCP].flags))
                
                if hasattr(pkt[TCP], 'options') and pkt[TCP].options:
                    opt_names = [str(opt[0]) for opt in pkt[TCP].options]
                    tcp_options.append(str(opt_names))
                else:
                    tcp_options.append("None")

            # 5. Livello HTTP
            if pkt.haslayer(HTTPRequest):
                http_layer = pkt[HTTPRequest]
                
                if hasattr(http_layer, 'Method') and http_layer.Method:
                    http_methods.append(http_layer.Method.decode('utf-8', errors='ignore'))
                
                if hasattr(http_layer, 'User_Agent') and http_layer.User_Agent:
                    http_user_agents.append(http_layer.User_Agent.decode('utf-8', errors='ignore'))

                if hasattr(http_layer, 'Accept_Language') and http_layer.Accept_Language:
                    http_accept_languages.append(http_layer.Accept_Language.decode('utf-8', errors='ignore'))

        except Exception as e:
            if not error_printed:
                print(f"[!] Attenzione: errore interno durante il parsing del pacchetto: {e}")
                error_printed = True
            continue
    
    # Arrotondamento per raggruppare i tempi inter-arrivo
    inter_arrival_rounded = [round(t, 3) for t in inter_arrival_times]

    # Costruzione del dizionario
    analysis = {
        "input_file": Path(pcap_path).name,
        "total_packets": len(packets),
        "features": {
            "packet_size": {
                "stats": safe_numeric_stats(packet_sizes),
                "top_values": top_frequencies(packet_sizes)
            },
            "inter_arrival_time": {
                "stats": safe_numeric_stats(inter_arrival_times),
                "top_values": top_frequencies(inter_arrival_rounded)
            },
            "ttl": {
                "stats": safe_numeric_stats(ttl_values),
                "top_values": top_frequencies(ttl_values),
                "entropy": calculate_entropy(ttl_values)
            },
            "ip_id": {  # Inserimento blocco IP ID nel JSON
                "stats": safe_numeric_stats(ip_id_values),
                "top_values": top_frequencies(ip_id_values),
                "entropy": calculate_entropy(ip_id_values)
            },
            "tcp": {
                "window_size": {
                    "stats": safe_numeric_stats(tcp_window_sizes),
                    "top_values": top_frequencies(tcp_window_sizes),
                    "entropy": calculate_entropy(tcp_window_sizes)
                },
                "seq_num": { 
                    "stats": safe_numeric_stats(tcp_seq_numbers),
                    "entropy": calculate_entropy(tcp_seq_numbers)
                },
                "flags_combinations": {
                    "top_values": top_frequencies(tcp_flags)
                },
                "options_combinations": {
                    "top_values": top_frequencies(tcp_options)
                }
            },
            "http": {
                "methods": {
                    "top_values": top_frequencies(http_methods)
                },
                "user_agents": {
                    "top_values": top_frequencies(http_user_agents),
                    "entropy": calculate_entropy(http_user_agents)
                },
                "accept_languages": {
                    "top_values": top_frequencies(http_accept_languages),
                    "entropy": calculate_entropy(http_accept_languages)
                }
            }
        }
    }

    return analysis

def main():
    print("[+] Inizio analisi.")
    try:
        result = analyze_pcap(INPUT_PCAP)

        # Assicura che la directory di output esista prima di scrivere
        OUTPUT_JSON.parent.mkdir(parents=True, exist_ok=True)

        with open(str(OUTPUT_JSON), "w", encoding="utf-8") as f:
            json.dump(result, f, indent=4)

        print("[+] Analisi completata.")
        print(f"[+] Pacchetti analizzati: {result['total_packets']}")
        print(f"[+] Profilo di baseline salvato in: {OUTPUT_JSON}")

    except FileNotFoundError:
        print(f"[!] File non trovato: {INPUT_PCAP}. Assicurati di aver inserito il file pcap nella cartella 'input'.", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"[!] Errore durante l'analisi: {exc}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()