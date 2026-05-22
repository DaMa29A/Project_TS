from pydantic import BaseModel
from typing import Any, Literal

class MutationStrategy(BaseModel):
    field_to_mutate: str
    new_value: Any
    reasoning: str

class NetworkFeedback(BaseModel):
    verdict: Literal["PASS", "BLOCK"] 
    reward: Literal[1, -1]           
    reason: str
    field_tested: str
    value_tested: Any