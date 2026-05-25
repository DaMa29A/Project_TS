import json
from pathlib import Path
from typing import Any
import numpy as np
from scipy.spatial.distance import jensenshannon

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
