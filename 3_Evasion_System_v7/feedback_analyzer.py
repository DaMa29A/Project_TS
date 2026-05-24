from scapy.all import AsyncSniffer, TCP, ICMP

class FeedbackAnalyzer:
    def __init__(self, target_ip: str, sport: int = None, timeout: float = 3.5):
        self.target_ip = target_ip
        self.sport = sport 
        self.timeout = timeout
        self.sniffer = None

    def start_listening(self):
        """Avvia lo sniffer in background filtrando solo la porta sorgente usata nel test."""
        # Se conosciamo la porta (V5) usiamo il filtro stretto, altrimenti (V6) usiamo il filtro largo
        if self.sport:
            filter_str = f"src host {self.target_ip} and (tcp dst port {self.sport} or icmp)"
        else:
            filter_str = f"src host {self.target_ip} and (tcp or icmp)"
        
        # count=5 invece di 1 per ignorare pacchetti "spazzatura" (es. RST del nostro kernel)
        self.sniffer = AsyncSniffer(filter=filter_str, count=5, timeout=self.timeout)
        self.sniffer.start()

    def get_reward(self) -> tuple[int, str, str]:
        """
        Valuta i pacchetti ricevuti iterando sui risultati.
        Restituisce: (reward, verdict, reason) per alimentare correttamente il main.
        """
        self.sniffer.join()
        packets = self.sniffer.results

        if not packets:
            print("[-] DROP/Timeout. Nessuna risposta utile. Reward: -1")
            return -1, "BLOCK", "Drop Silente (Timeout)"
            
        for pkt in packets:
            if pkt.haslayer(TCP):
                flags = pkt[TCP].flags
                if flags == 0x12 or flags == "SA": # SYN-ACK
                    print("[+] SYN-ACK reale sniffato! Evasione riuscita. Reward: +1")
                    return 1, "PASS", "SYN-ACK ricevuto"
                elif flags == 0x14 or flags == "RA" or flags == "R": # RST o RST-ACK
                    print("[-] RST sniffato. Connessione bloccata dal target. Reward: -1")
                    return -1, "BLOCK", "Connessione resettata (RST)"
                    
            elif pkt.haslayer(ICMP):
                print("[-] ICMP Error sniffato. Reward: -1")
                return -1, "BLOCK", "Errore ICMP ricevuto"

        print("[-] Risposte inattese o fuori standard. Assumo fallimento. Reward: -1")
        return -1, "BLOCK", "Risposta non standard"