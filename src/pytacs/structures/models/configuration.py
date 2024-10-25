from typing import List

from pytacs.structures.models.base import BaseModel
from pytacs.structures.models.ldap import LDAPConfiguration
from pytacs.structures.models.server import ServerConfiguration
from pytacs.structures.modules import SupportedModules


class BaseOptions(BaseModel):
    foreground: bool  # Should process run in foreground or background?
    syslog: bool  # Should log messages go to syslog?


class Configuration(BaseModel):
    options: BaseOptions
    modules: List[SupportedModules]
    ldap: LDAPConfiguration
    servers: List[ServerConfiguration]
