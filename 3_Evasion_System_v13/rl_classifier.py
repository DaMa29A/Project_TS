import pandas as pd
import joblib
import os
import hashlib
from sklearn.ensemble import RandomForestClassifier
from sklearn.exceptions import NotFittedError
from constants import RL_MEMORY
from models import PacketState

class RLMutationClassifier:
    def __init__(self, min_samples_to_train=5):
        """
        Inizializza il classificatore ibrido di Reinforcement Learning.
        min_samples_to_train: Numero di iterazioni minime prima di addestrare il modello.
        """
        self.memory = []
        # max_depth=5 evita l'overfitting su un numero ridotto di campioni
        self.model = RandomForestClassifier(n_estimators=50, random_state=42, max_depth=5)
        self.min_samples_to_train = min_samples_to_train
        self.is_trained = False
        

    def _extract_features(self, state: PacketState) -> dict:
        """
        Trasforma lo stato completo del pacchetto in feature per il Random Forest.
        """
        features = {}
        # Campi numerici diretti
        features['ttl'] = float(state.ttl)
        features['win_size'] = float(state.win_size)
        features['seq_num'] = float(state.seq_num)

        # Feature Hashing per le stringhe (Flags e User-Agent)
        # hash_flags = int(hashlib.md5(state.flags.encode('utf-8')).hexdigest(), 16) % 10000
        # features['flags_encoded'] = float(hash_flags)
        
        hash_ua = int(hashlib.md5(state.user_agent.encode('utf-8')).hexdigest(), 16) % 10000
        features['ua_encoded'] = float(hash_ua)

        hash_al = int(hashlib.md5(state.accept_language.encode('utf-8')).hexdigest(), 16) % 10000 if state.accept_language else 0
        features['al_encoded'] = float(hash_al)
            
        return features


    def add_experience(self, state: PacketState, reward: int):
        """Aggiunge l'esito di un intero pacchetto alla memoria."""
        features = self._extract_features(state)
        
        # 1 = PASS (Evasione), 0 = BLOCK
        features['target'] = 1 if reward == 1 else 0
        self.memory.append(features)
        
        if len(self.memory) >= self.min_samples_to_train:
            self._train_model()


    def _train_model(self):
        """Addestra il Random Forest Classifier sui dati."""
        df = pd.DataFrame(self.memory)
        
        # Il modello non può allenarsi se ha visto solo successi (tutti 1) o solo fallimenti (tutti 0)
        if len(df['target'].unique()) > 1:
            X = df.drop('target', axis=1)
            y = df['target']
            self.model.fit(X, y)
            self.is_trained = True
        else:
            self.is_trained = False
        

    def predict_success_probability(self, state: PacketState) -> float:
        """
        Prevede la probabilità di successo di una specifica mutazione.
        Ritorna un float da 0.0 (Blocco Sicuro) a 1.0 (Successo Sicuro).
        Se il modello non è ancora addestrato, ritorna 0.5 (Incertezza totale).
        """
        if not self.is_trained:
            return 0.5 
            
        try:
            features = self._extract_features(state)
            X_test = pd.DataFrame([features])
            prob_success = self.model.predict_proba(X_test)[0][1]
            return round(prob_success, 2)
            
        except NotFittedError:
            return 0.5

            
    def get_memory_stats(self):
        """
        Analizza retrospettivamente l'intero storico delle esperienze 
        raccolte fino a quel momento per calcolare l'efficacia delle tecniche provate.
        Dice letteralmente:
        "Fino a questo momento, ho provato a lanciare X pacchetti contro il firewall. 
        Il tasso di successo globale è Y%. Ma guardando solo le ultime 50 mosse 
        (dopo che ho iniziato a capire le regole), il successo è Z%."
        """
        df = pd.DataFrame(self.memory)
        if df.empty:
            return "Memoria Vuota"
        
        success_rate = (df['target'].sum() / len(df)) * 100

        recent = df.tail(50)
        success_rate_recent = (recent['target'].sum() / len(recent)) * 100
        
        return f"Campioni Totali: {len(df)} | Evasion Rate Totale: {success_rate:.1f}% | Evasion Rate (Recent [Last 50]): {success_rate_recent:.1f}%"


    def save_state(self, filepath=RL_MEMORY):
        """Salva il modello addestrato e lo storico della memoria su disco."""
        directory = os.path.dirname(filepath)
        
        if directory and not os.path.exists(directory):
            os.makedirs(directory, exist_ok=True)
            print(f"\n[RL Classifier] Creata nuova directory per il salvataggio: '{directory}'")

        state = {
            'model': self.model,
            'memory': self.memory,
            'is_trained': self.is_trained
        }
        
        joblib.dump(state, filepath)
        print(f"\n[RL Classifier] Stato salvato con successo ({len(self.memory)} campioni).")


    def load_state(self, filepath=RL_MEMORY):
        """Carica il modello e la memoria dal disco, ripristinando l'addestramento."""
        if os.path.exists(filepath):
            try:
                state = joblib.load(filepath)
                self.model = state['model']
                self.memory = state['memory']
                self.is_trained = state['is_trained']
                print(f"\n[RL Classifier] Memoria ripristinata. Campioni caricati: {len(self.memory)}.")
            except Exception as e:
                print(f"\n[!] Errore durante il caricamento con joblib: {e}. Ripartirò da zero.")
        else:
            print(f"\n[RL Classifier] Nessun file '{filepath}' trovato. Inizializzazione da zero.")