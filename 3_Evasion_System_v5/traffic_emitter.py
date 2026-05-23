from scapy.all import send

def emit_packet(mutated_packet):
    """Invia fisicamente il pacchetto."""
    send(mutated_packet, verbose=0)