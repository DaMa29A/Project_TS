from scapy.all import IP, TCP
from models import MutationStrategy
from protocol_mutator import apply_mutation
from constants import TARGET_IP

class EvasionProxy:
    def __init__(self, mutation: MutationStrategy = None):
        self.mutation = mutation

    def manage_packet(self, packet):
        # Estraiamo il payload grezzo e lo diamo in pasto a Scapy
        scapy_packet = IP(packet.get_payload())
        
        # Controlliamo se è un pacchetto TCP diretto al target
        if scapy_packet.haslayer(TCP) and scapy_packet[IP].dst == TARGET_IP:
            # print(f"TCP Packet to {TARGET_IP} intercepted!")
            
            if self.mutation:
                print(f"[Proxy] Applico strategia: {self.mutation.field_to_mutate} -> {self.mutation.new_value}")
                
                # Creiamo la versione modificata del pacchetto
                pk_mod = apply_mutation(scapy_packet, self.mutation)

                # RICALCOLO DEI CHECKSUM
                # Eliminandoli, costringiamo Scapy a ricalcolarli matematicamente 
                del pk_mod[IP].chksum
                del pk_mod[TCP].chksum
                
                # SOVRASCRIVIAMO IL PACCHETTO NELLA CODA
                packet.set_payload(bytes(pk_mod))

        # Lasciamo passare il pacchetto (che ora contiene il payload modificato)
        packet.accept()