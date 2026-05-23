from scapy.all import IP, TCP
from models import MutationStrategy
from constants import TARGET_IP

class EvasionProxy:
    def __init__(self, mutation : MutationStrategy = None):
        self.mutation = mutation

    def manage_packet(self, packet):
        # Convertiamo il pacchetto in un formato che Scapy può leggere
        scapy_packet = IP(packet.get_payload())
        
        # Controlliamo se è un pacchetto TCP e se è diretto al nostro target
        if scapy_packet.haslayer(TCP) and scapy_packet[IP].dst == TARGET_IP:
            print(f"TCP Packet to {TARGET_IP} intercepted!")
            if self.mutation:
                print("Applying mutation strategy...")

        # Accettiamo il pacchetto (lo lasciamo passare)
        packet.accept()