import re
import json
import random
import time
from scapy.all import IP, TCP, Raw
from models import MutationStrategy, PacketState
from rl_classifier import RLMutationClassifier
from protocol_mutator import apply_outbound_mutations, apply_inbound_translation
from constants import TARGET_IP

class EvasionProxy:
    def __init__(self, mutation: MutationStrategy = None):
        self.mutation = mutation
        
        self.p_state = PacketState(ttl=0, win_size=0, seq_num=0, ip_id=0, user_agent="") 
        
        self.classifier = RLMutationClassifier(min_samples_to_train=5)
        self.classifier.load_state()

        self.flow_state = {}

        self.last_packet_time = None
        self.jitter_config = None
    
    
    def complete_p_state(self, pk):
        if self.p_state.ttl == 0:
            self.p_state.ttl = pk[IP].ttl
            
        if self.p_state.win_size == 0:
            self.p_state.win_size = pk[TCP].window
        
        if self.p_state.seq_num == 0:
            self.p_state.seq_num = pk[TCP].seq
        
        if self.p_state.user_agent == "" and pk.haslayer(Raw):
            try:
                # Decodifichiamo il payload in testo ignorando i caratteri non validi
                payload = pk[Raw].load.decode('utf-8', errors='ignore')
                
                # Cerchiamo la riga che inizia con "User-Agent:"
                match = re.search(r'User-Agent:\s*(.+)\r\n', payload)
                if match:
                    self.p_state.user_agent = match.group(1).strip()
                    print(f"[Proxy] Baseline User-Agent catturato: {self.p_state.user_agent}")
            except Exception:
                pass
        
        if self.p_state.ip_id == 0:
            self.p_state.ip_id = pk[IP].id
            print(f"id: {pk[IP].id}")
    

    def get_flow_id(self, pkt):
        if pkt[IP].dst == TARGET_IP:
            return (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
        else:
            return (pkt[IP].dst, pkt[TCP].dport, pkt[IP].src, pkt[TCP].sport)


    def manage_packet(self, packet):
        old_p_state = self.p_state

        # Estraiamo il payload grezzo e lo diamo in pasto a Scapy
        scapy_packet = IP(packet.get_payload())

        if not scapy_packet.haslayer(TCP):
            packet.accept()
            return

        if scapy_packet[IP].dst != TARGET_IP and scapy_packet[IP].src != TARGET_IP:
            packet.accept()
            return
        
        fid = self.get_flow_id(scapy_packet)

        if fid not in self.flow_state:
            self.flow_state[fid] = {
                "locked": False,
                "seq_delta": 0,
                "established": False
            }
        
        state = self.flow_state[fid]

        # -------------------------------------------------
        # CLIENT -> SERVER (USCITA)
        # -------------------------------------------------
        if scapy_packet[IP].dst == TARGET_IP:
            self.complete_p_state(scapy_packet)

            if self.mutation:

                match self.mutation.field_to_mutate:
                    case "ttl":
                        self.p_state.ttl = self.mutation.new_value
                    case "win_size":
                        self.p_state.win_size = self.mutation.new_value
                    case "seq_num":
                        self.p_state.seq_num = self.mutation.new_value
                    case "ip_id":
                        self.p_state.ip_id = int(self.mutation.new_value)
                    case _: # 'default'
                        pass
            
                """prob = self.classifier.predict_success_probability(self.p_state)
                print(f"Probability of Success: {prob * 100:.0f}%")"""
                    
                # print(f"[Proxy] Applico strategia: {self.mutation.field_to_mutate} -> {self.mutation.new_value}")
                
                print(f"DEBUG ip_id type: {type(self.p_state.ip_id)}, value: {self.p_state.ip_id}")

                # Deleghiamo la modifica al protocol_mutator!
                scapy_packet = apply_outbound_mutations(
                    scapy_packet, 
                    self.p_state, 
                    self.mutation,
                    state
                )
        
        # -------------------------------------------------
        # SERVER -> CLIENT (ENTRATA)
        # -------------------------------------------------
        else:
            # Deleghiamo la traduzione inversa al protocol_mutator!
            scapy_packet = apply_inbound_translation(scapy_packet, state)
        

        # -------------------------------------------------
        # JITTER (ritardo tra pacchetti con distribuzione di Poisson)
        # -------------------------------------------------
        if self.mutation and self.mutation.field_to_mutate == "jitter":
            config = self.mutation.new_value
            if isinstance(config, str):
                try:
                    config = json.loads(config)
                except json.JSONDecodeError:
                    config = {}
            mean_ms = config.get("mean_delay_ms", 20)  # media in millisecondi
            if mean_ms > 0:
                # Distribuzione esponenziale (Poisson process)
                delay_sec = random.expovariate(1.0 / (mean_ms / 1000.0))
                delay_sec = min(delay_sec, 0.5)  # max 500 ms
                print(f"[Jitter] Ritardo di {delay_sec*1000:.2f} ms (mean={mean_ms}ms)")
                time.sleep(delay_sec)
        
        # -------------------------------------------------
        # Retransmission simulation (packet loss)
        # -------------------------------------------------
        if self.mutation and self.mutation.field_to_mutate == "retransmit":
            cfg = self.mutation.new_value
            if isinstance(cfg, str):
                cfg = json.loads(cfg)
            drop_prob = cfg.get("drop_probability", 0.1)
            # Evita di droppare pacchetti critici (SYN, FIN, RST)
            if not (scapy_packet[TCP].flags & 0x07):
                if random.random() < drop_prob:
                    print(f"[Retransmit] Pacchetto droppato (simulata perdita), TCP ritrasmetterà")
                    packet.drop()
                    return

        # -------------------------------------------------
        # RICALCOLO CHECKSUM E RILASCIO
        # -------------------------------------------------
        del scapy_packet[IP].chksum
        del scapy_packet[TCP].chksum

        try:
            payload_bytes = bytes(scapy_packet)

            packet.set_payload(payload_bytes)
            packet.accept()
            
        except Exception as e:
            print(f"[Proxy ERROR] Valore LLM illegale! Impossibile generare il pacchetto: {e}")
            self.p_state = old_p_state
            packet.drop()