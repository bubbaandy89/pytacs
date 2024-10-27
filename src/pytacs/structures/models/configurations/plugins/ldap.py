from typing import List, Optional

from ldap3.core.exceptions import LDAPInvalidDnError
from ldap3.utils import dn
from pydantic import IPvAnyAddress, field_validator

from pytacs.structures.models.configurations.plugins.base import PluginConfiguration


class LDAPConfiguration(PluginConfiguration):
    host_name: Optional[str] = None
    host_ip: Optional[IPvAnyAddress] = None
    port: int = 389
    dn_format: str  # Example "cn=%s,ou=people,dc=haqa,dc=net"
    attributes: List[str]
    values: List[str]

    @field_validator("dn_format")
    @classmethod
    def validate_dn_format(cls, v: str):
        try:
            dn.parse_dn(v)
        except LDAPInvalidDnError:
            raise ValueError(f"Invalid DN format: {v}")

    @field_validator("*", mode="before")
    def check_not_empty(cls, v):
        if isinstance(v, str) and v.strip() == "":
            return None
        return v

    @property
    def host(self) -> str:
        return str(self.host_ip) or self.host_name or "127.0.0.1"
