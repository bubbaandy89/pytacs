import json
from pathlib import Path

from pytacs.structures.models.configurations.configuration import Configuration


def read_config_file(config_file_path: Path) -> Configuration:
    with open(config_file_path, "r") as f:
        return Configuration.model_validate(json.loads(f.read()))
