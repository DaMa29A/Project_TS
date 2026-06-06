import json
import sys
from pathlib import Path
from scapy.all import rdpcap, IP, TCP
from scapy.layers.http import HTTPRequest
from scapy.layers.tls.all import TLS
from scapy.layers.tls.handshake import TLSClientHello
from constants import INPUT_PCAP, OUTPUT_JSON
from utils import safe_numeric_stats, top_frequencies, calculate_entropy
from zeek_parser import get_zeek_http, get_zeek_flow, get_zeek_tls

def analyze_pcap(pcap_path):
    packets = rdpcap(str(pcap_path))

    # --- 1. Variabili per Scapy ---
    packet_sizes = []
    ttl_values = []
    ip_id_values = []
    tcp_window_sizes = []
    inter_arrival_times = []
    tcp_flags = []
    tcp_options = []
    tcp_seq_numbers = []
    http_accept_languages = []
    tls_record_sizes = []      
    tls_ciphersuites = [] # Nuova lista per le ciphersuite di Scapy in esadecimale

    last_time = None 
    error_printed = False

    # --- 2. Scapy (Livello Basso) ---
    for pkt in packets:
        try:
            if IP in pkt and pkt[IP].dst != "192.168.20.10":
                continue 

            packet_sizes.append(len(pkt))

            if hasattr(pkt, 'time') and pkt.time is not None:
                current_time = float(pkt.time)
                if last_time is not None:
                    diff = round(current_time - last_time, 6)
                    inter_arrival_times.append(diff)
                last_time = current_time

            if IP in pkt:                   
                ttl_values.append(int(pkt[IP].ttl)) 
                ip_id_values.append(int(pkt[IP].id))

            if TCP in pkt:                  
                tcp_window_sizes.append(int(pkt[TCP].window)) 
                tcp_seq_numbers.append(int(pkt[TCP].seq))
                tcp_flags.append(str(pkt[TCP].flags))
                
                if hasattr(pkt[TCP], 'options') and pkt[TCP].options:
                    opt_names = [str(opt[0]) for opt in pkt[TCP].options]
                    tcp_options.append(str(opt_names))
                else:
                    tcp_options.append("None")

            # Estrazione Accept-Language
            if pkt.haslayer(HTTPRequest):
                http_layer = pkt[HTTPRequest]
                if hasattr(http_layer, 'Accept_Language') and http_layer.Accept_Language:
                    http_accept_languages.append(http_layer.Accept_Language.decode('utf-8', errors='ignore'))
            
            # Estrazione TLS
            if pkt.haslayer(TLS):
                if hasattr(pkt[TLS], 'len') and pkt[TLS].len is not None:
                    tls_record_sizes.append(int(pkt[TLS].len))
            
                # Estraiamo le Ciphersuite dal Client Hello
                if pkt.haslayer(TLSClientHello):
                    hello = pkt[TLSClientHello]
                    if hasattr(hello, 'ciphers') and hello.ciphers:
                        for cipher in hello.ciphers:
                            tls_ciphersuites.append(hex(cipher))

        except Exception as e:
            if not error_printed:
                print(f"[!] Attenzione: errore interno durante il parsing del pacchetto: {e}")
                error_printed = True
            continue
    
    inter_arrival_rounded = [round(t, 3) for t in inter_arrival_times]

    # --- 3. Zeek (Livello Sessione/Flusso) ---
    print("[+] Recupero dati da Zeek...")
    zeek_flow_data = get_zeek_flow()
    zeek_http_data = get_zeek_http()

    # --- 4. Costruzione del dizionario ---
    analysis = {
        "input_file": Path(pcap_path).name,
        "total_packets": len(packets),
        "flow_profiling": zeek_flow_data.get("flow_profiling", {}),
        "features": {
            "packet_size": {
                "stats": safe_numeric_stats(packet_sizes),
                "top_values": top_frequencies(packet_sizes)
            },
            "inter_arrival_time": {
                "stats": safe_numeric_stats(inter_arrival_times),
                "top_values": top_frequencies(inter_arrival_rounded)
            },
            "ip":{
                "ttl": {
                    "stats": safe_numeric_stats(ttl_values),
                    "top_values": top_frequencies(ttl_values),
                    "entropy": calculate_entropy(ttl_values)
                },
                "ip_id": {
                    "stats": safe_numeric_stats(ip_id_values),
                    "top_values": top_frequencies(ip_id_values),
                    "entropy": calculate_entropy(ip_id_values)
                },
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
                    "top_values": top_frequencies(tcp_flags),
                    "entropy": calculate_entropy(tcp_flags) 
                },
                "options_combinations": {
                    "top_values": top_frequencies(tcp_options),
                    "entropy": calculate_entropy(tcp_options)
                }
            },
            "http": {
                "methods": zeek_http_data.get("http", {}).get("methods", {}),
                "user_agents": zeek_http_data.get("http", {}).get("user_agents", {}),
                "accept_languages": {
                    "top_values": top_frequencies(http_accept_languages),
                    "entropy": calculate_entropy(http_accept_languages)
                }
            },
            "tls": {
                "record_size": {
                    "stats": safe_numeric_stats(tls_record_sizes),
                    "top_values": top_frequencies(tls_record_sizes)
                },
                "ciphersuites_combinations": {
                    "top_values": top_frequencies(tls_ciphersuites),
                    "entropy": calculate_entropy(tls_ciphersuites)
                }
            }
        }
    }

    return analysis

def main():
    print("[+] Inizio analisi.")
    try:
        result = analyze_pcap(INPUT_PCAP)

        OUTPUT_JSON.parent.mkdir(parents=True, exist_ok=True)

        with open(str(OUTPUT_JSON), "w", encoding="utf-8") as f:
            json.dump(result, f, indent=4)

        print("[+] Analisi completata.")
        print(f"[+] Profilo di baseline ibrido salvato in: {OUTPUT_JSON}")

    except FileNotFoundError:
        print(f"[!] File pcap non trovato: {INPUT_PCAP}.", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"[!] Errore durante l'analisi: {exc}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()