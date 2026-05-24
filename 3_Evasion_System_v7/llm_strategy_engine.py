from langchain_ollama import ChatOllama
from langchain_core.messages import SystemMessage, HumanMessage, AIMessage
import json
import re
from models import NetworkFeedback, MutationStrategy


class LLMEvasionStrategyEngine:
    def __init__(self, ollama_url: str, model: str):
        self.llm = ChatOllama(
            model=model,
            base_url=ollama_url,
            temperature=0.9,
            top_p=0.95,
            repeat_penalty=1.15,
            format="json"
        )

        self.history = []
    
    def generate_strategy(self, baseline: dict | None = None, last_feedback: NetworkFeedback | None = None) -> MutationStrategy:
        baseline_info = json.dumps(baseline) if baseline else "Unknown (No baseline provided)"

        feedback_info = "No previous feedback."
        if last_feedback:
            feedback_info = (
                f"Tested Field: {last_feedback.field_tested} -> {last_feedback.value_tested}\n"
                f"Verdict: {last_feedback.verdict}\n"
                f"Reward: {last_feedback.reward}\n"
                f"Reason: {last_feedback.reason}"
            )

        # 2. Costruzione del messaggio umano corrente
        current_human_message = HumanMessage(content=(
            f"BASELINE TRAFFIC PROFILE:\n{baseline_info}\n\n"
            f"LAST DROP FEEDBACK:\n{feedback_info}\n\n"
            "Based on the BASELINE TRAFFIC PROFILE and the LAST DROP FEEDBACK, decide which field to mutate among 'ttl', 'win_size', 'seq_num'. "
            "Generate the JSON for the next mutation strategy."
        ))

        # 3. Costruzione del prompt completo con la cronologia
        messages = [
            SystemMessage(content=(
                "You are an expert Red Teamer.\n\n"
                "Your objective is to generate dynamic protocol mutations to evade detection.\n"
                "You can mutate ONLY ONE of the following fields at a time:\n"
                "- 'ttl' (Integer, IP Time-To-Live. Valid range: 1 to 255)\n"
                "- 'win_size' (Integer, TCP Window Size. Valid range: 0 to 65535)\n"
                "- 'seq_num' (Integer, TCP Sequence Number. Valid range: 0 to 4294967295)\n"
                "Constraints:\n"
                "1. Output ONLY a valid JSON object. No markdown, no intro, no outro.\n"
                "2. Use this exact schema:\n"
                "{\n"
                '  "field_to_mutate": "<must be exactly one of: ttl, win_size, seq_num>",\n'
                '  "new_value": <integer for ttl/win_size/seq_num>,\n'
                '  "reasoning": "<short chain-of-thought explanation of why you chose this>"\n'
                "}\n"
            )),
            *self.history[-10:], # Teniamo gli ultimi 10 messaggi di storia
            current_human_message
        ]

        # 4. Chiamata all'LLM
        result = self.llm.invoke(messages)
        raw_output = result.content.strip()

        # 5. Pulizia robusta del Markdown (RegEx)
        match = re.search(r"```(?:json)?\n?(.*?)\n?```", raw_output, re.DOTALL)
        if match:
            raw_output = match.group(1).strip()

        # 6. Parsing e creazione dell'oggetto
        try:
            strategy_dict = json.loads(raw_output)
            
            # Creiamo l'oggetto strutturato invece di un semplice dizionario
            strategy_obj = MutationStrategy(
                field_to_mutate=strategy_dict.get("field_to_mutate", "error_missing_field"),
                new_value=strategy_dict.get("new_value", "error_missing_value"),
                reasoning=strategy_dict.get("reasoning", "System Error: No reasoning provided by LLM.")
            )

            strategy_obj = self._normalize_strategy(strategy_obj)
            
            # Salviamo il VERO contesto nella cronologia per mantenere memoria del feedback
            self.history.append(current_human_message)
            self.history.append(AIMessage(content=result.content))
            
            return strategy_obj
            
        except json.JSONDecodeError:
            print(f"Error decoding JSON from LLM: {raw_output}")
            # Fallback in caso di allucinazioni dell'LLM
            return MutationStrategy(
                field_to_mutate="error_json_decode", 
                new_value="invalid_format", 
                reasoning="System Error: Failed to parse LLM output. The LLM did not output a valid JSON."
            )
    
    def _normalize_strategy(self, strategy: MutationStrategy) -> MutationStrategy:
        if strategy.field_to_mutate == "flags" and isinstance(strategy.new_value, str):
            print(f"Before normalization: {strategy}")
            raw_flags = strategy.new_value.upper()
            flag_map = {
                'SYN': 'S', 'ACK': 'A', 'FIN': 'F', 'RST': 'R',
                'PSH': 'P', 'URG': 'U', 'ECE': 'E', 'CWR': 'C'
            }
            # Crea un pattern dinamico: r'\b(SYN|ACK|FIN|RST|PSH|URG|ECE|CWR)\b'
            pattern = r'\b(' + '|'.join(flag_map.keys()) + r')\b'
            
            # Cerca tutte le occorrenze esatte nel testo
            found_words = re.findall(pattern, raw_flags)
            if found_words:
                # Mappa le parole trovate nei caratteri Scapy (usando un set per evitare duplicati come "SS")
                normalized = "".join(set(flag_map[word] for word in found_words))
                strategy.new_value = normalized
        return strategy
            