from scapy.all import sniff, IP, TCP, ICMP, Raw

class FeedbackAnalyzer:

    def __init__(self, target_ip, target_port, iface, timeout=4):
        self.target_ip = target_ip
        self.target_port = target_port
        self.iface = iface
        self.timeout = timeout

        self.score = -1
        self.reason = "TIMEOUT"

        self._done = False

        # state tracking
        self.synack_seen = False
        self.data_seen = False  # NUOVO: traccia se riceviamo payload dal server

    # ----------------------------
    # FLOW FILTER
    # ----------------------------
    def match_flow(self, pkt):
        if IP not in pkt:
            return False

        ip = pkt[IP]

        if ip.src != self.target_ip:
            return False

        if TCP in pkt:
            tcp = pkt[TCP]
            # Solo risposte server → client
            if tcp.sport != self.target_port:
                return False
            return True

        if ICMP in pkt:
            return True

        return False

    # ----------------------------
    # CORE LOGIC
    # ----------------------------
    def analyze(self, pkt):
        if self._done:
            return

        if not self.match_flow(pkt):
            return

        # ---------------- TCP ----------------
        if TCP in pkt:
            tcp = pkt[TCP]
            flags = tcp.flags

            # SYN-ACK = L4 Handshake completato
            if flags == 0x12:
                self.synack_seen = True

            # RST = Explicit reject dal firewall o server
            elif flags & 0x04:
                self.score = -1
                self.reason = "RST_BLOCK"
                self._done = True
                return

            # FIN = Il server sta chiudendo la connessione
            elif flags & 0x01:
                # Se il server chiude prima di averci inviato dati, 
                # la nostra richiesta non è mai arrivata (Drop silenzioso)
                if not self.data_seen:
                    self.score = -1
                    self.reason = "SERVER_CLOSED_NO_DATA"
                    self._done = True
                return

            # PAYLOAD DATI = L'evasione L7 ha funzionato!
            # Controlliamo se c'è il layer "Raw" (che in Scapy contiene il payload HTTP)
            # o se il flag PSH (0x08) è attivo.
            if Raw in pkt or (flags & 0x08):
                self.data_seen = True
                self.score = 1
                self.reason = "ACCEPTED_WITH_DATA"
                self._done = True
                return

        # ---------------- ICMP ----------------
        elif ICMP in pkt:
            icmp = pkt[ICMP]
            # ICMP Destination Unreachable
            if icmp.type == 3:
                self.score = -1
                self.reason = "ICMP_BLOCK"
                self._done = True
                return

    # ----------------------------
    # STOP CONDITION
    # ----------------------------
    def stop_filter(self, pkt):
        return self._done

    # ----------------------------
    # FINAL RESULT AFTER TIMEOUT
    # ----------------------------
    def run(self):
        sniff(
            iface=self.iface,
            filter=f"host {self.target_ip}",
            prn=self.analyze,
            store=False,
            timeout=self.timeout,
            stop_filter=self.stop_filter
        )

        # Decisione allo scadere del timeout di sniff
        if not self._done:
            if self.synack_seen and not self.data_seen:
                # Handshake L4 OK, ma niente dati L7 in risposta.
                # È un "Silent Drop" del firewall sul nostro pacchetto HTTP.
                self.score = -1
                self.reason = "SILENT_DROP_L7"
            else:
                self.score = -1
                self.reason = "TIMEOUT_L4"

        return self.score, self.reason