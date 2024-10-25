from pydantic import SecretStr
from pydantic.networks import IPvAnyAddress

from pytacs.structures.models.base import BaseModel


class ClientConfiguration(BaseModel):
    name: str
    ip_address: IPvAnyAddress
    secret: SecretStr
