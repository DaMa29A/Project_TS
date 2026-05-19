from pydantic import BaseModel
from typing import Any

class MutationStrategy(BaseModel):
    field_to_mutate: str
    new_value: Any
    reasoning: str