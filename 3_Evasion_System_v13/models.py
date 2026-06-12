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

class PacketState(BaseModel):
    ttl: int = 0
    win_size: int = 0
    seq_num: int = 0
    ip_id : int = 0
    flags: Any = None
    user_agent: str = ""
    accept_language: str = ""
    referer: str = ""
    content_type: str = ""