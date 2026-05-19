from scapy.all import IP, TCP
from models import MutationStrategy


def craft_mutated_packet(target_ip: str, target_port: int, strategy: MutationStrategy):
    """Crea un pacchetto TCP SYN mutato in base alla strategia."""
    
    # Partiamo da un pacchetto base
    base_ip = IP(dst=target_ip)
    base_tcp = TCP(dport=target_port, flags="S", seq=1000)

    # Applichiamo la mutazione
    if strategy.field_to_mutate == "ttl":
        base_ip.ttl = int(strategy.new_value)
        print(f"[Mutator] Mutazione applicata: IP TTL = {strategy.new_value}")
    else:
        print(f"[Mutator] Nessuna logica di mutazione definita per {strategy.field_to_mutate}")

    # Assembliamo il pacchetto
    mutated_packet = base_ip / base_tcp
    return mutated_packet