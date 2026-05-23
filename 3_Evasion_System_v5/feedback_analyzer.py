from scapy.all import AsyncSniffer, TCP, ICMP

class FeedbackAnalyzer:
    def __init__(self, target_ip: str, sport: int, timeout: float = 2.5):
        self.target_ip = target_ip
        self.sport = sport  # Nuova variabile: ascoltiamo solo le risposte dirette a noi!
        self.timeout = timeout
        self.sniffer = None

    def start_listening(self):
        """Avvia lo sniffer in background filtrando solo la porta sorgente usata nel test."""
        # Filtro BPF strettissimo: Solo dal target e verso la nostra porta dinamica
        filter_str = f"src host {self.target_ip} and (tcp dst port {self.sport} or icmp)"
        
        # count=5 invece di 1 per ignorare pacchetti "spazzatura" (es. RST del nostro kernel)
        self.sniffer = AsyncSniffer(filter=filter_str, count=5, timeout=self.timeout)
        self.sniffer.start()

    def get_reward(self) -> int:
        """Valuta i pacchetti ricevuti iterando sui risultati."""
        self.sniffer.join()
        packets = self.sniffer.results

        if not packets:
            print("[-] DROP/Timeout. Nessuna risposta utile. Reward: -1")
            return -1
            
        # Analizziamo tutti i pacchetti catturati invece di fermarci al primo
        for pkt in packets:
            if pkt.haslayer(TCP):
                flags = pkt[TCP].flags
                if flags == 0x12: # SYN-ACK
                    print("[+] SYN-ACK reale sniffato! Evasione riuscita. Reward: +1")
                    return 1
                elif flags == 0x14: # RST o RST-ACK
                    print("[-] RST sniffato. Connessione bloccata dal target. Reward: -1")
                    return -1
                    
            elif pkt.haslayer(ICMP):
                print("[-] ICMP Error sniffato. Reward: -1")
                return -1

        print("[-] Risposte inattese o fuori standard. Assumo fallimento. Reward: -1")
        return -1