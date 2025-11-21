import json
from pathlib import Path
from typing import Dict, Any, Union
from datetime import datetime

class EnhancedJSONEncoder(json.JSONEncoder):
    """
    A custom JSON encoder that handles datetime and Path objects.
    """
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, Path):
            return str(obj)
        # Handle sets by converting them to lists
        if isinstance(obj, set):
            return list(obj)
        return super().default(obj)

def save_json(data: Dict[str, Any], file_path: Union[str, Path], indent: int = 2):
    """
    Save data to a JSON file with pretty formatting using the enhanced encoder.
    """
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, cls=EnhancedJSONEncoder, indent=indent)

def load_json(file_path: Union[str, Path]) -> Dict[str, Any]:
    """
    Load data from a JSON file.
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def load_config(config_path: Path) -> Dict[str, Any]:
    """
    Load a configuration file from a given path. This function now correctly
    expects the full path to the config file and does not add any prefixes.
    """
    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    return load_json(config_path)
