from ipaddress import IPv4Address
from pathlib import Path
from typing import List

from pydantic import field_validator
from pydantic.networks import IPvAnyAddress

from pytacs.structures.models.base import BaseModel
from pytacs.structures.models.client import ClientConfiguration


class ServerConfiguration(BaseModel):
    plugin_name: str
    listening_address: IPvAnyAddress = IPv4Address("127.0.0.1")
    listening_port: int = 49
    clients: List[ClientConfiguration]
    accounting_logfile: str = "/var/log/tacacs_accounting.log"

    @field_validator("accounting_logfile")
    @classmethod
    def validate_path(cls, value) -> Path:
        # If value is already a Path object, return it
        if isinstance(value, Path):
            return value

        # Convert string or other types to Path
        try:
            path = Path(value)
            return path.resolve()  # Resolves to absolute path
        except Exception as e:
            raise ValueError(f"Invalid path format: {e}")
