"""Load and validate NetShield JSON configuration files."""

import json
from pathlib import Path
from typing import Any


def load_json(file_path: Path) -> dict[str, Any]:
    """Return validated JSON configuration data."""
    if not file_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {file_path}")

    with file_path.open("r", encoding="utf-8") as config_file:
        data = json.load(config_file)

    if not isinstance(data, dict):
        raise ValueError(f"Configuration must be a JSON object: {file_path}")

    return data
