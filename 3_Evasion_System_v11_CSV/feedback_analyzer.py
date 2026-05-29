import threading
from scapy.all import sniff, IP, ICMP, TCP


class FeedbackAnalyzer:
    def __init__(self, target_ip: str, interface: str = "eth0", timeout: float = 3.5):
        self.target_ip = target_ip
        self.interface = interface
        self.timeout = timeout

        self.feedback_score = -1
        self.reason = "TIMEOUT"

        self._thread = None

    def analyze_response(self, pkt):

        if IP not in pkt:
            return

        ip = pkt[IP]

        # Solo traffico dal target
        if ip.src != self.target_ip:
            return

        # --- ICMP ---
        if ICMP in pkt:
            if pkt[ICMP].type == 0:
                self.feedback_score = 1
                self.reason = "ICMP_REPLY"
            elif pkt[ICMP].type == 3:
                self.feedback_score = -1
                self.reason = "ICMP_UNREACHABLE"

        # --- TCP ---
        elif TCP in pkt:
            tcp = pkt[TCP]
            flags = tcp.flags

            # SYN-ACK
            if flags == 0x12:
                self.feedback_score = 1
                self.reason = "SYN_ACK"

            # RST / RST-ACK
            elif flags in (0x14, 0x04):
                self.feedback_score = -1
                self.reason = "TCP_RST"

    def run(self):
        self.feedback_score = -1
        self.reason = "TIMEOUT"

        sniff(
            iface=self.interface,
            prn=self.analyze_response,
            store=False,
            timeout=self.timeout
        )

    def start(self):
        self._thread = threading.Thread(target=self.run, daemon=True)
        self._thread.start()

    def wait(self):
        if self._thread:
            self._thread.join()
        return self.feedback_score, self.reason