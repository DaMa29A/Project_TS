import re
import json
import random
import time
from scapy.all import IP, TCP, Raw, send
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
        
        if self.p_state.ip_id == 0:
            self.p_state.ip_id = pk[IP].id
            #print(f"id: {pk[IP].id}")
        
        if self.p_state.user_agent == "" and pk.haslayer(Raw):
            try:
                # Decodifichiamo il payload in testo ignorando i caratteri non validi
                payload = pk[Raw].load.decode('utf-8', errors='ignore')
                
                # Cerchiamo la riga che inizia con "User-Agent:"
                if self.p_state.user_agent == "":
                    match = re.search(r'User-Agent:\s*(.+)\r\n', payload)
                    if match:
                        self.p_state.user_agent = match.group(1).strip()
                        #print(f"[Proxy] Baseline User-Agent catturato: {self.p_state.user_agent}")
                if self.p_state.referer == "":
                    match = re.search(r'Referer:\s*(.+)\r\n', payload, re.IGNORECASE)
                    if match:
                        self.p_state.referer = match.group(1).strip()
                        #print(f"[Proxy] Baseline Referer catturato: {self.p_state.referer}")
                if self.p_state.content_type == "":
                    match = re.search(r'Content-Type:\s*(.+)\r\n', payload, re.IGNORECASE)
                    if match:
                        self.p_state.content_type = match.group(1).strip()
                if self.p_state.accept_language == "":
                    match = re.search(r'Accept-Language:\s*(.+)\r\n', payload, re.IGNORECASE)
                    if match:
                        self.p_state.accept_language = match.group(1).strip()
            except Exception:
                pass
         

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
                "established": False,
                "fragmented_seqs": set(),       # Aggiunto per fragmentation HTTP
                "stored_headers": None,         # memorizza gli header HTTP
                "headers_seq": 0,               # sequence number del pacchetto degli header
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
                        self.p_state.ttl = int(self.mutation.new_value)
                    case "win_size":
                        self.p_state.win_size = int(self.mutation.new_value)
                    case "seq_num":
                        self.p_state.seq_num = int(self.mutation.new_value)
                    case "ip_id":
                        self.p_state.ip_id = int(self.mutation.new_value)
                    case "flags":
                        flags_value = self.mutation.new_value
                        if isinstance(flags_value, str):
                            try:
                                flags_value = json.loads(flags_value)
                            except json.JSONDecodeError:
                                print(f"[!] Errore parsing JSON per flags: {flags_value}")
                                flags_value = {}
                        self.p_state.flags = flags_value
                    case _: # 'default'
                        pass
            
                """prob = self.classifier.predict_success_probability(self.p_state)
                print(f"Probability of Success: {prob * 100:.0f}%")"""
                    
                # print(f"[Proxy] Applico strategia: {self.mutation.field_to_mutate} -> {self.mutation.new_value}")
                
                #print(f"DEBUG ip_id type: {type(self.p_state.ip_id)}, value: {self.p_state.ip_id}")

                # Deleghiamo la modifica al protocol_mutator!
                scapy_packet = apply_outbound_mutations(
                    scapy_packet, 
                    self.p_state, 
                    self.mutation,
                    state
                )
            
            # -------------------------------------------------
            # TCP FRAGMENTATION (HTTP BODY SPLIT a Livello 3)
            # -------------------------------------------------
            if self.mutation and self.mutation.field_to_mutate == "http_split":
                cfg = self.mutation.new_value
                if isinstance(cfg, str):
                    cfg = json.loads(cfg)

                num_chunks = int(cfg.get("num_chunks", 3))
                delay = float(cfg.get("delay_ms", 20)) / 1000.0

                if scapy_packet.haslayer(Raw):
                    payload = scapy_packet[Raw].load
                    sep = b"\r\n\r\n"

                    # --- CASO 1: pacchetto che contiene solo gli header (termina con \r\n\r\n) ---
                    if sep in payload and payload.endswith(sep):
                        # Controlliamo se è una richiesta che prevede un body (POST/PUT/PATCH con Content-Length > 0)
                        headers_raw = payload.split(sep, 1)[0].decode('utf-8', errors='ignore')
                        method = headers_raw.split(' ')[0] if ' ' in headers_raw else ''
                        has_body = False
                        if method.upper() in ('POST', 'PUT', 'PATCH'):
                            cl_match = re.search(r'Content-Length:\s*(\d+)', headers_raw, re.IGNORECASE)
                            if cl_match and int(cl_match.group(1)) > 0:
                                has_body = True

                        # Inoltriamo sempre il pacchetto degli header (non va droppato)
                        if not has_body:
                            print("[TCP Frag] Richiesta senza body, nessuna frammentazione.")
                            packet.accept()
                            return

                        # Salviamo i dati necessari per calcolare il SEQ del body
                        state["stored_headers_seq"] = scapy_packet[TCP].seq
                        state["headers_payload_len"] = len(payload)   # lunghezza totale del pacchetto headers (include \r\n\r\n)
                        state["has_body"] = True
                        print(f"[TCP Frag] Header inoltrati (SEQ={scapy_packet[TCP].seq}, len={len(payload)} byte), attendo body.")
                        # NON droppare il pacchetto: va accettato
                        packet.accept()
                        return

                    # --- CASO 2: abbiamo già inoltrato gli header e questo è il pacchetto del body ---
                    elif state.get("has_body") and state.get("stored_headers_seq") is not None:
                        body = payload
                        if len(body) == 0:
                            print("[TCP Frag] Body vuoto, nessuna frammentazione.")
                            state["has_body"] = False
                            packet.accept()
                            return

                        # Evita di riframmentare ritrasmissioni
                        seq_key = (scapy_packet[TCP].seq, len(body))
                        if seq_key in state["fragmented_seqs"]:
                            print(f"[TCP Frag] Ritrasmissione già gestita SEQ={scapy_packet[TCP].seq}, ignoro.")
                            packet.drop()
                            return
                        state["fragmented_seqs"].add(seq_key)

                        total = len(body)
                        print(f"[TCP Frag] Corpo del body ricevuto: {total} byte, SEQ={scapy_packet[TCP].seq}")
                        # Calcolo dimensioni dei frammenti
                        base = total // num_chunks
                        rem = total % num_chunks
                        body_frags = []
                        pos = 0
                        for i in range(num_chunks):
                            size = base + (1 if i < rem else 0)
                            if size > 0:
                                body_frags.append(body[pos:pos+size])
                            pos += size

                        print(f"[TCP Frag] Suddivisione in {len(body_frags)} frammenti (richiesti {num_chunks})")
                        for i, f in enumerate(body_frags):
                            print(f"  frammento {i+1}: dimensione={len(f)} byte, primi 20 byte: {f[:20].hex()}, frammento: {f}")

                        # Blocca il pacchetto originale del body
                        packet.drop()

                        # Il body inizia dopo gli header già inviati
                        body_start_seq = state["stored_headers_seq"] + state["headers_payload_len"]
                        current_seq = body_start_seq
                        print(f"[TCP Frag] SEQ iniziale per il body: {body_start_seq}")

                        for idx, frag in enumerate(body_frags):
                            frag_pkt = scapy_packet.copy()
                            if Raw in frag_pkt:
                                del frag_pkt[Raw]

                            frag_pkt = frag_pkt / Raw(load=frag)
                            frag_pkt[TCP].seq = current_seq
                            current_seq += len(frag)

                            # PSH solo sull'ultimo frammento
                            if idx == len(body_frags) - 1:
                                frag_pkt[TCP].flags |= 0x08  # PSH
                            else:
                                frag_pkt[TCP].flags &= ~0x08  # toglie PSH se presente

                            del frag_pkt[IP].chksum
                            del frag_pkt[TCP].chksum
                            frag_pkt[IP].len = None

                            send(frag_pkt, verbose=False)
                            print(f"  Inviato frammento {idx+1}: SEQ={frag_pkt[TCP].seq}, LEN={len(frag)}, PSH={'SI' if idx == len(body_frags)-1 else 'NO'}")
                            if idx < len(body_frags) - 1 and delay > 0:
                                time.sleep(delay)

                        sent_total = sum(len(f) for f in body_frags)
                        print(f"[TCP Frag] Totale inviato: {sent_total} byte (attesi {total})")

                        # Resetta lo stato
                        state["has_body"] = False
                        state["stored_headers_seq"] = None
                        state["headers_payload_len"] = None
                        return

                    else:
                        packet.accept()
                        return
             
  
        
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
            mean_ms = float(self.mutation.new_value)   # media in millisecondi [Da 5 a 100 come valore]
            if mean_ms > 0:
                # Distribuzione esponenziale (Poisson process)
                delay_sec = random.expovariate(1.0 / (mean_ms / 1000.0))
                delay_sec = min(delay_sec, 0.5)  # max 500 ms
                print(f"[Jitter] Ritardo di {delay_sec*1000:.2f} ms (mean={mean_ms}ms)")
                time.sleep(delay_sec)
            #self.p_state.jitter = mean_ms
        
        # -------------------------------------------------
        # Retransmission simulation (packet loss)
        # -------------------------------------------------
        if self.mutation and self.mutation.field_to_mutate == "retransmit":
            drop_prob = float(self.mutation.new_value) #drop_probability
            # Evita di droppare pacchetti critici (SYN, FIN, RST)
            if not (scapy_packet[TCP].flags & 0x07):
                if random.random() < drop_prob:
                    print(f"[Retransmit] Pacchetto droppato (simulata perdita), TCP ritrasmetterà")
                    packet.drop()
                    return
            #self.p_state.jitter = drop_prob

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