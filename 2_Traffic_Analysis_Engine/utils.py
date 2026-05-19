import statistics
from collections import Counter
import math

def safe_numeric_stats(values):
    """
    Calcola statistiche su una lista di valori numerici.
    Parametri:
        values (list): lista di numeri (es. packet sizes, TTL, window size)
    Ritorna:
        dict: statistiche principali in formato JSON.
    """
    if not values:
        return {
            "count": 0,
            "min": None,
            "max": None,
            "mean": None,
            "median": None,
            "stdev": None
        }

    return {
        "count": len(values),   # Numero totale di campioni
        "min": min(values),     # Valore minimo
        "max": max(values),     # Valore massimo
        "mean": round(statistics.mean(values), 3),      # Valore medio arrotondato a 3 decimali
        "median": round(statistics.median(values), 3),  # Valore mediano arrotondato a 3 decimali
        "stdev": round(statistics.stdev(values), 3) if len(values) > 1 else 0.0 # Deviazione standard arrotondata a 3 decimali, 0 se c'è un solo campione
    }


def top_frequencies(values, top_n=10):
    """Calcola le frequenze dei valori e restituisce i più comuni.
    Parametri:
        values (list): lista di valori
        top_n (int): numero di valori più frequenti da restituire
    Ritorna:
        list: lista di dizionari contenenti i valori e le loro frequenze
    """
    if not values:
        return []
    freq = Counter(values).most_common(top_n)
    return [{"value": v, "count": c} for v, c in freq]


def calculate_entropy(values):
    """
    Calcola l'entropia di Shannon su una lista di valori.
    Valori prossimi allo 0 indicano bassa variabilità (tutti uguali),
    valori alti indicano alta variabilità (molto rumore).
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