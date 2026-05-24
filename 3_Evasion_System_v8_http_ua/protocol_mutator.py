from scapy.all import IP, TCP

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