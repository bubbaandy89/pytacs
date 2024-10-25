from ipaddress import IPv4Address
from typing import List

from pydantic.networks import IPvAnyAddress

from pytacs.structures.models.base import BaseModel
from pytacs.structures.models.client import ClientConfiguration


class ServerConfiguration(BaseModel):
    name: str
    listening_address: IPvAnyAddress = IPv4Address("127.0.0.1")
    listening_port: int = 49
    clients: List[ClientConfiguration]
