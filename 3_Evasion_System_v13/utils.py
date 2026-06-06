import json
from pathlib import Path
from typing import Any
import numpy as np
import csv
from typing import List
from scipy.spatial.distance import jensenshannon
from models import MutationStrategy

def load_json(path: str | Path, default: Any = None) -> Any:
    """
    Loads data from a JSON file. Returns a default value if the file does not exist
    or if the JSON data is invalid or corrupted.
    """
    file_path = Path(path)

    if not file_path.exists():
        return default

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
            
    except json.JSONDecodeError:
        print(f"Warning: The file {file_path} contains invalid JSON. Returning default.")
        return default


def save_json(path: str | Path, data: Any) -> None:
    """
    Saves a Python object to a JSON file. Automatically creates any missing
    parent directories in the path.
    """
    file_path = Path(path)

    file_path.parent.mkdir(parents=True, exist_ok=True)

    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)


def get_mutation_from_csv(filepath: str) -> List[MutationStrategy]:
    strategie_estratte = []
    
    # Campi che sappiamo dover essere per forza numeri interi
    integer_fields = ["ttl", "win_size", "seq_num"]

    try:
        with open(filepath, mode='r', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            
            for row in reader:
                # FIX: Usiamo (or "") per evitare che un valore None causi un errore con .strip()
                field = (row.get("mutated_field") or "").strip()
                raw_value = (row.get("mutated_value") or "").strip()
                reasoning = (row.get("reasoning") or "").strip()
                
                # Ignoriamo le righe vuote o malformate
                if not field:
                    continue

                # Conversione del tipo: se è un campo di rete, lo trasformiamo in int
                parsed_value = raw_value
                if field in integer_fields:
                    try:
                        parsed_value = int(raw_value)
                    except ValueError:
                        print(f"[!] Attenzione: Impossibile convertire '{raw_value}' in intero per il campo '{field}'. Lo mantengo come stringa.")

                # Creazione dell'oggetto Pydantic usando il tuo modello
                strategy = MutationStrategy(
                    field_to_mutate=field,
                    new_value=parsed_value,
                    reasoning=reasoning
                )
                
                strategie_estratte.append(strategy)
                
        return strategie_estratte

    except FileNotFoundError:
        print(f"[Errore] Il file '{filepath}' non è stato trovato.")
        return []
    except Exception as e:
        print(f"[Errore] Si è verificato un problema durante la lettura del CSV: {e}")
        return []


def append_mutation_to_csv(filepath: str | Path, strategy: MutationStrategy, reward: int, active_mutations) -> None:
    """
    Startegy active: {'user_agent': 'BOt', 'ttl': 64}
    Salva una singola MutationStrategy in un file CSV.
    Se il file non esiste, lo crea e inserisce l'intestazione.
    Se esiste, appende la nuova riga.
    """
    file_path = Path(filepath)
    
    # Controlla se il file esiste prima di aprirlo (serve per capire se scrivere l'header)
    file_exists = file_path.exists()
    
    # Crea le cartelle parent se non esistono (es. la cartella "mutations")
    file_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Apri in modalità 'a' (append) per accodare i dati
    with open(file_path, mode='a', newline='', encoding='utf-8') as file:
        fieldnames = ["reward", "mutated_field", "mutated_value", "ttl", "win_size", "seq_num", "user_agent", "accept_language", "http_split", "reasoning"]
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        
        # Scrivi gli header solo se il file è appena stato creato
        if not file_exists:
            writer.writeheader()
            
        # Scrivi i dati della mutazione mappandoli sulle colonne corrette
        writer.writerow({
            "reward": reward,
            "mutated_field": strategy.field_to_mutate,
            "mutated_value": strategy.new_value,
            "reasoning": strategy.reasoning,
            "ttl": active_mutations.get("ttl", ""),
            "win_size": active_mutations.get("win_size", ""), 
            "seq_num": active_mutations.get("seq_num", ""),
            "user_agent": active_mutations.get("user_agent", ""), 
            "accept_language": active_mutations.get("accept_language", ""), 
            "http_split": active_mutations.get("http_split", "")
        })



def calculate_js_distance(baseline_top_values, mutated_values):
    """
    Calcola la Jensen-Shannon Distance per un campo specifico.
    """
    if not mutated_values:
        return 0.0 # Nessuna mutazione effettuata, distanza 0

    # 1. Estrai i conteggi dalla baseline
    baseline_counts = {item['value']: item['count'] for item in baseline_top_values}
    
    # 2. Conta le frequenze dei valori mutati
    mutated_counts = {val: mutated_values.count(val) for val in set(mutated_values)}
    
    # 3. Crea un set di tutti i possibili valori per allineare gli array
    all_keys = set(baseline_counts.keys()).union(set(mutated_counts.keys()))
    
    p = [] # Array Baseline
    q = [] # Array Traffico Mutato
    
    for key in all_keys:
        p.append(baseline_counts.get(key, 0))
        q.append(mutated_counts.get(key, 0))
        
    # 4. Converti in probabilità (normalizzazione)
    p = np.array(p, dtype=float)
    q = np.array(q, dtype=float)
    
    sum_p, sum_q = np.sum(p), np.sum(q)
    
    if sum_p > 0: p /= sum_p
    if sum_q > 0: q /= sum_q
    
    # 5. Calcola e restituisci la distanza (tra 0 e 1)
    return jensenshannon(p, q)
