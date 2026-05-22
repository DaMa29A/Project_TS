import random
from scapy.all import IP, TCP
from models import MutationStrategy

def craft_mutated_packet(target_ip: str, target_port: int, strategy: MutationStrategy):
    """Crea un pacchetto TCP SYN mutato in base alla strategia, con porte e seq randomizzati."""
    
    # Randomizziamo per evitare i filtri anti-flood/correlation degli IDS
    sport = random.randint(1024, 65535)
    default_seq = random.randint(0, 2**32 - 1) 
    
    base_ip = IP(dst=target_ip)
    base_tcp = TCP(sport=sport, dport=target_port, flags="S", seq=default_seq)

    # Applichiamo la mutazione TTL
    if strategy.field_to_mutate == "ttl":
        base_ip.ttl = int(strategy.new_value)
        print(f"[Mutator] Mutazione applicata: IP TTL = {strategy.new_value}")
    # Applichiamo la mutazione WINDOWS SIZE
    elif strategy.field_to_mutate == "win_size":
        base_tcp.window = int(strategy.new_value)
        print(f"[Mutator] Mutazione applicata: TCP Window Size={strategy.new_value} | sport={sport}")
    # Applichiamo la mutazione SEQUENCE NUMBER
    elif strategy.field_to_mutate == "seq_num":
        base_tcp.seq = int(strategy.new_value)
        print(f"[Mutator] Mutazione applicata: TCP Sequence Number = {strategy.new_value}")
    # Applichiamo la mutazione TCP FLAGS
    elif strategy.field_to_mutate == "flags":
        base_tcp.flags = str(strategy.new_value)
        print(f"[Mutator] Mutazione applicata: TCP Flags = [{strategy.new_value}]")
    else:
        print(f"[Mutator] Nessuna logica definita per {strategy.field_to_mutate}")

    mutated_packet = base_ip / base_tcp
    return mutated_packet