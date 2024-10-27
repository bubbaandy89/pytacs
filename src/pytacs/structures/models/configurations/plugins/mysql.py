from typing import Optional

from pydantic import IPvAnyAddress, field_validator

from pytacs.structures.models.configurations.plugins.base import PluginConfiguration


class MySQLConfiguration(PluginConfiguration):
    host_name: Optional[str] = None
    host_ip: Optional[IPvAnyAddress] = None
    port: int = 3306
    table_name: str

    @field_validator("*", mode="before")
    def check_not_empty(cls, v):
        if isinstance(v, str) and v.strip() == "":
            return None
        return v

    @property
    def host(self) -> str:
        return str(self.host_ip) or self.host_name or "127.0.0.1"
