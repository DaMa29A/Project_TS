import statistics
from collections import Counter
import math

def safe_numeric_stats(values):
    """
    Calcola statistiche su una lista di valori numerici.
    """
    if not values:
        return {
            "min": None,
            "max": None,
            "mean": None,
            "stdev": None
        }

    return {
        "min": min(values),
        "max": max(values),
        "mean": round(statistics.mean(values), 3),
        "stdev": round(statistics.stdev(values), 3) if len(values) > 1 else 0.0
    }

def top_frequencies(values, top_n=10):
    """Calcola i valori più frequenti e restituisce solo una lista piatta."""
    if not values:
        return []
    
    freq = Counter(values).most_common(top_n)
    # Ritorna solo il valore 'v', ignorando il conteggio 'c'
    return [v for v, c in freq]

def calculate_entropy(values):
    """
    Calcola l'entropia di Shannon su una lista di valori.
    """
    if not values:
        return 0.0
    
    counts = Counter(values)
    total_elements = len(values)
    
    entropy = 0.0
    for count in counts.values():
        probability = count / total_elements
        entropy -= probability * math.log2(probability)
        
    return round(entropy, 4)