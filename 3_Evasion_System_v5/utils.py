import json
from pathlib import Path
from typing import Any

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