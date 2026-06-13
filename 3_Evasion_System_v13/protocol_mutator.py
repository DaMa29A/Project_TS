from scapy.all import IP, TCP, Raw
from utils import tcp_flags_str_to_int

def apply_outbound_mutations(scapy_packet, p_state, mutation, flow_state):
    """
    Applica le mutazioni al traffico in USCITA (Client -> Server).
    Gestisce sia le mutazioni stateless (ttl, win) che stateful (seq_num).
    """
    tcp = scapy_packet[TCP]
    MOD = 2**32

    # ------- Modifica ttl ------- 
    if p_state.ttl != scapy_packet[IP].ttl:
        scapy_packet[IP].ttl = p_state.ttl
    
    # ------- Modifica Window Size ------- 
    if p_state.win_size != tcp.window:
        tcp.window = p_state.win_size
    
    # ------- Modifica IP ID Statico -------
    if p_state.ip_id != scapy_packet[IP].id:
        scapy_packet[IP].id = p_state.ip_id

    # ------- Modifica Sequence Number ------- 
    if (mutation.field_to_mutate == "seq_num"):
        target_seq = p_state.seq_num
        
        # Se è il SYN iniziale, calcoliamo il Delta e blocchiamo lo stato
        if (tcp.flags & 0x02) and not flow_state["locked"]:
            flow_state["locked"] = True
            if target_seq is not None:
                flow_state["seq_delta"] = (int(target_seq) - tcp.seq) % MOD
                print(f"[Mutator] Delta SEQ calcolato: {flow_state['seq_delta']}")
            else:
                flow_state["seq_delta"] = 0

        # Applichiamo la traslazione del Sequence Number a TUTTI i pacchetti in uscita
        if flow_state["locked"] and flow_state["seq_delta"] != 0:
            tcp.seq = (tcp.seq + flow_state["seq_delta"]) % MOD
    
    # ------- Modifica Flags ------- 
    print("aaaa")
    if (mutation.field_to_mutate == "flags"):
        print(f"FLAGS DEBUG -- \nScapyPacket:{scapy_packet}\nmutation:{mutation}")
        has_payload = len(scapy_packet[TCP].payload) > 0 if Raw in scapy_packet else False
        print(f"HasPAyload: {has_payload}")
        new_flags = apply_tcp_flags_mutation(tcp, p_state.flags, flow_state, has_payload)
        tcp.flags = new_flags
        print(f"[Mutator] TCP flags: {p_state.flags['action']} -> {int(new_flags):02x}")
        #print(f"[Mutator] TCP flags: {p_state.flags['action']} -> {new_flags:02x}")

    return scapy_packet


def apply_inbound_translation(scapy_packet, flow_state):
    """
    Ripristina i pacchetti in ENTRATA (Server -> Client) per il Kernel locale.
    Traduce l'ACK del server sottraendo il delta del Sequence Number.
    """
    tcp = scapy_packet[TCP]
    MOD = 2**32

    # Traduzione inversa dell'ACK
    if flow_state["locked"] and flow_state["seq_delta"] != 0:
        if tcp.flags & 0x10:  # Se è presente il flag ACK
            old_ack = tcp.ack
            tcp.ack = (old_ack - flow_state["seq_delta"]) % MOD
            # print(f"[Mutator NAT] ACK tradotto: {old_ack} -> {tcp.ack}")

    # Tracking stato connessione
    if (tcp.flags & 0x12) and not flow_state["established"]:
        pass # Visto SYN-ACK
    if tcp.flags & 0x10:
        flow_state["established"] = True

    return scapy_packet


def apply_tcp_flags_mutation(tcp, flags_dict, flow_state, packet_has_payload):
    """
    flags_dict: {'action': 'add'|'set'|'remove'|'toggle', 'value': intero o stringa, 'apply_to': ...}
    flow_state: dict con 'established'
    packet_has_payload: bool (len(tcp.payload)>0)
    """
    action = flags_dict.get('action', 'add')
    raw_value = flags_dict.get('value', 0)
    apply_to = flags_dict.get('apply_to', 'all_packets')
    
    # Determina se questo pacchetto deve essere mutato
    should = False
    if apply_to == 'all_packets':
        should = True
    elif apply_to == 'syn_only':
        should = (tcp.flags & 0x02) != 0
    elif apply_to == 'fin_only':
        should = (tcp.flags & 0x01) != 0
    elif apply_to == 'ack_only':
        should = (tcp.flags & 0x10) != 0 and (tcp.flags & 0x1F) == 0x10
    elif apply_to == 'data_packets_only':
        should = packet_has_payload or (tcp.flags & 0x08)
    elif apply_to == 'established_only':
        should = flow_state.get('established', False)
    else:
        should = True
    
    if not should:
        return tcp.flags
    
    # Converte il valore in intero bitmask
    if isinstance(raw_value, str):
        bitmask = tcp_flags_str_to_int(raw_value)
    else:
        bitmask = int(raw_value)
    
    old_flags = tcp.flags
    
    if action == 'set':
        new_flags = bitmask
    elif action == 'add':
        new_flags = old_flags | bitmask
    elif action == 'remove':
        new_flags = old_flags & ~bitmask
    elif action == 'toggle':
        new_flags = old_flags ^ bitmask
    else:
        new_flags = old_flags
    
    # Sicurezza: preserva almeno SYN se è il primo pacchetto? Potresti aggiungere una protezione.
    # Per ora restituisci il nuovo valore.
    return new_flags