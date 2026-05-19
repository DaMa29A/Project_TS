import random
from constants import HTTP_TARGET, HTTPS_TARGET, HTTPS_RATIO, MISSING_PATHS, MISSING_RATIO, EXISTING_PATHS

# Sceglie con probabilità minore di HTTPS_RATIO
# una richiesta HTTPS altriementi HTTP
def pick_base_target():
    if random.random() < HTTPS_RATIO:
        return HTTPS_TARGET
    return HTTP_TARGET

# Sceglie con probabilità minore di MISSING_RATIO
# un path non esistente altriementi esistente
def pick_path():
    if random.random() < MISSING_RATIO:
        return random.choice(MISSING_PATHS)
    return random.choice(EXISTING_PATHS)

# Pausa tra richiesta e un altra
def sample_delay():
    r = random.random()
    if r < 0.70:
        return random.uniform(0.4, 1.5) # pausa breve
    if r < 0.90:
        return random.uniform(1.5, 4.0) # pausa media
    return random.uniform(4.0, 8.0)     # pausa lunga