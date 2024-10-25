from enum import Enum


class SupportedModules(str, Enum):
    TACACS_SERVER = "pyt_tacacs_server"
    LDAP_ATTRIBUTES = "pyt_ldap_attributes"
