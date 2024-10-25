from enum import Enum


class SupportedModule(str, Enum):
    TACACS_SERVER = "pyt_tacacs_server"
    LDAP_ATTRIBUTES = "pyt_ldap_attributes"
    MYSQL = "pyt_mysql"
