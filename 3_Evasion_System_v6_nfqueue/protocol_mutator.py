import random
from scapy.all import IP, TCP
from models import MutationStrategy

def create_baseline_packet(target_ip: str, target_port: int, default_ttl=64, default_win_size=126) -> IP:
    """
    Crea da zero un pacchetto TCP SYN standard (baseline).
    Genera porte e sequence number casuali per evitare filtri anti-flood.
    """
    sport = random.randint(1024, 65535)
    default_seq = random.randint(0, 2**32 - 1) 
    
    # Costruiamo i livelli (Layers) standard
    base_ip = IP(dst=target_ip, ttl=default_ttl)
    base_tcp = TCP(sport=sport, dport=target_port, flags="S", seq=default_seq, window=default_win_size)
    
    # Assembliamo il pacchetto
    baseline_packet = base_ip / base_tcp
    return baseline_packet


def apply_mutation(base_packet: IP, strategy: MutationStrategy) -> IP:
    """
    Prende in input un pacchetto esistente e una strategia.
    Ne crea una copia profonda e vi applica le mutazioni richieste, 
    restituendo il pacchetto mutato pronto per l'invio.
    """
    # 1. Creiamo una copia per NON sporcare il pacchetto originale
    mutated_packet = base_packet.copy()
    
    # 2. Applichiamo la mutazione al livello corretto usando la sintassi mutated_packet[Layer]
    if strategy.field_to_mutate == "ttl":
        mutated_packet[IP].ttl = int(strategy.new_value)
        print(f"[Mutator] Mutazione applicata: IP TTL = {strategy.new_value}")
        
    elif strategy.field_to_mutate == "win_size":
        mutated_packet[TCP].window = int(strategy.new_value)
        print(f"[Mutator] Mutazione applicata: TCP Window Size = {strategy.new_value}")
        
    elif strategy.field_to_mutate == "seq_num":
        mutated_packet[TCP].seq = int(strategy.new_value)
        print(f"[Mutator] Mutazione applicata: TCP Sequence Number = {strategy.new_value}")
        
    elif strategy.field_to_mutate == "flags":
        mutated_packet[TCP].flags = str(strategy.new_value)
        print(f"[Mutator] Mutazione applicata: TCP Flags = [{strategy.new_value}]")
        
    else:
        print(f"[Mutator] ERRORE: Nessuna logica definita per il campo '{strategy.field_to_mutate}'")

    # 3. Restituiamo la copia mutata
    return mutated_packet