from scapy.all import send

def emit_packet(mutated_packet):
    """Invia fisicamente il pacchetto sulla rete (senza aspettare risposte)."""
    # verbose=0 evita che scapy stampi "Sent 1 packets." ad ogni ciclo
    send(mutated_packet, verbose=0)