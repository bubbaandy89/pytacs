from datetime import datetime
from typing import List

from pydantic import IPvAnyAddress

from pytacs.structures.models.base import BaseModel


class BaseAuthorizationDetails(BaseModel):
    """Authorization details should inherit from this model"""

    timestamp: datetime
    user_name: str
    nas_ip: IPvAnyAddress
    nas_port: str
    nac_ip: IPvAnyAddress
    command: str
    command_args: List[str]
