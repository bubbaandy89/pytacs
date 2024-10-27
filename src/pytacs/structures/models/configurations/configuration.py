from typing import List, Literal

from pytacs.structures.models.base import BaseModel
from pytacs.structures.models.configurations.plugins.ldap import LDAPConfiguration
from pytacs.structures.models.configurations.plugins.mysql import MySQLConfiguration
from pytacs.structures.models.server import ServerConfiguration
from pytacs.structures.modules import SupportedModule


class BaseOptions(BaseModel):
    foreground: bool  # Should process run in foreground or background?
    syslog: bool  # Should log messages go to syslog?
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]


class Configuration(BaseModel):
    options: BaseOptions
    modules: List[SupportedModule]
    ldap: LDAPConfiguration
    servers: List[ServerConfiguration]
    mysql: MySQLConfiguration
