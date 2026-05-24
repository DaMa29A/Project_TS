from scapy.all import IP, TCP
from constants import TARGET_IP

class EvasionProxy:
    def __init__(self, mutation=None):
        self.mutation = mutation
        self.flow_state = {}

    def flow_id(self, pkt):
        # NORMALIZZAZIONE: Invertiamo IP e Porte se il pacchetto sta tornando,
        # in modo che "fid" sia sempre identico sia all'andata che al ritorno.
        if pkt[IP].dst == TARGET_IP:
            return (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
        else:
            return (pkt[IP].dst, pkt[TCP].dport, pkt[IP].src, pkt[TCP].sport)

    def manage_packet_seq(self, packet):

        scapy_packet = IP(packet.get_payload())

        if not scapy_packet.haslayer(TCP):
            packet.accept()
            return

        tcp = scapy_packet[TCP]

        # filtro target
        if scapy_packet[IP].dst != TARGET_IP and scapy_packet[IP].src != TARGET_IP:
            packet.accept()
            return

        fid = self.flow_id(scapy_packet)
        MOD = 2**32

        # init state
        if fid not in self.flow_state:
            self.flow_state[fid] = {
                "locked": False,
                "seq_delta": None,
                "established": False
            }

        state = self.flow_state[fid]

        # -------------------------------------------------
        # CLIENT -> SERVER (Traffico in uscita verso il Target)
        # -------------------------------------------------
        if scapy_packet[IP].dst == TARGET_IP:

            # 1) lock su SYN iniziale
            if (tcp.flags & 0x02) and not state["locked"]:
                state["locked"] = True
                
                # Calcoliamo il delta solo se la strategia ci dice di mutare seq_num
                if self.mutation and self.mutation.field_to_mutate == "seq_num":
                    state["seq_delta"] = (int(self.mutation.new_value) - tcp.seq) % MOD
                    print(f"[FLOW LOCK] C->S delta calcolato = {state['seq_delta']}")
                else:
                    state["seq_delta"] = 0

            # 2) applica shift a TUTTI i pacchetti prima e dopo la connessione
            # Se trasliamo il SYN, dobbiamo traslare per forza anche l'HTTP GET!
            if state["locked"] and state["seq_delta"] and state["seq_delta"] != 0:
                old_seq = tcp.seq
                tcp.seq = (old_seq + state["seq_delta"]) % MOD
                # print(f"[SEQ] C->S {old_seq} -> {tcp.seq}")

        # -------------------------------------------------
        # SERVER -> CLIENT (Traffico in entrata dal Target)
        # -------------------------------------------------
        else:
            # 1) TRADUZIONE INVERSA DELL'ACK
            # Se abbiamo alterato il SEQ in andata, dobbiamo ripristinare l'ACK in ritorno
            if state["locked"] and state["seq_delta"] is not None and state["seq_delta"] != 0:
                if tcp.flags & 0x10:  # Se è presente il flag ACK (es. SYN-ACK, PSH-ACK)
                    old_ack = tcp.ack
                    # Sottraiamo il delta (usando modulo MOD per gestire i wrap-around)
                    tcp.ack = (old_ack - state["seq_delta"]) % MOD
                    print(f"[ACK] S->C tradotto: {old_ack} -> {tcp.ack} per il Kernel di Kali")

            # 2) GESTIONE STATO
            if tcp.flags & 0x12 and not state["established"]:
                # SYN-ACK visto
                pass

            if tcp.flags & 0x10:
                state["established"] = True

        # -------------------------------------------------
        # checksum fix
        # -------------------------------------------------
        del scapy_packet[IP].chksum
        del scapy_packet[TCP].chksum

        packet.set_payload(bytes(scapy_packet))
        packet.accept()