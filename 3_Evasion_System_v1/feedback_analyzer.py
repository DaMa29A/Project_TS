from scapy.all import AsyncSniffer, TCP, ICMP

class FeedbackAnalyzer:
    def __init__(self, target_ip: str, timeout: float = 1.5):
        self.target_ip = target_ip
        self.timeout = timeout
        self.sniffer = None

    def start_listening(self):
        """Avvia lo sniffer in background (non blocca il codice)."""
        # Filtriamo solo TCP o ICMP dal target per evitare rumore di fondo
        filter_str = f"src host {self.target_ip} and (tcp or icmp)"
        self.sniffer = AsyncSniffer(filter=filter_str, count=1, timeout=self.timeout)
        self.sniffer.start()

    def get_reward(self) -> int:
        """Aspetta la fine del timeout/cattura e valuta il pacchetto."""
        self.sniffer.join() # Attende che lo sniffer finisca il suo lavoro
        packets = self.sniffer.results

        if not packets:
            print("[-] DROP/Timeout. Nessuna risposta sniffata. Reward: -1")
            return -1
            
        response = packets[0]
        
        # Controllo livello TCP
        if response.haslayer(TCP):
            flags = response[TCP].flags
            if flags == 0x12: # SYN-ACK
                print("[+] SYN-ACK sniffato! Evasione riuscita. Reward: +1")
                return 1
            elif flags == 0x14: # RST-ACK
                print("[-] RST sniffato. Connessione bloccata. Reward: -1")
                return -1
                
        # Controllo livello ICMP
        elif response.haslayer(ICMP):
            print("[-] ICMP Error sniffato. Reward: -1")
            return -1

        print("[-] Risposta inattesa. Assumo fallimento. Reward: -1")
        return -1