"""
PyTACS LDAP User Source

Must have the following options defined
    host	The hostname or ip address of the LDAP server
    port	The port number the LDAP server is listening on
    dnfmt	An LDAP DN with the token %s where the username should be inserted
"""

from functools import cached_property
from ipaddress import IPv4Address
from typing import Dict, List, Optional

from ldap3 import Connection, Server
from ldap3.core.exceptions import LDAPBindError

from pytacs.plugins.base.user_source import UserSource
from pytacs.structures.exceptions import PyTACSError
from pytacs.structures.models.authorization import BaseAuthorizationDetails
from pytacs.structures.models.configurations.plugins.ldap import LDAPConfiguration


class LDAPConnectionError(PyTACSError):
    pass


class LdapSource(UserSource):
    "A user source based on an LDAP directory"

    __required__: List[str] = ["host", "port", "dnfmt"]

    def __init__(self, name: str, modconfig: LDAPConfiguration) -> None:
        "Prepare LDAP settings"
        super().__init__(name, modconfig)

    @cached_property
    def ldap_server(self) -> Server:
        " "
        return Server(self.modconfig.host, int(self.modconfig.port))

    def get_user(self, user: str, password: str) -> Optional[Dict[str, List[str]]]:
        " "
        base_dn: str = self.modconfig.dn_format.format(user)
        try:
            connection = Connection(
                self.ldap_server, user=user, password=password, auto_bind=True
            )
        except LDAPBindError as e:
            raise LDAPConnectionError("Unable to bind to LDAP server") from e

        res = connection.search(
            search_base=base_dn,
            search_filter=f"(&(objectClass=person)(uid={user}))",
        )

        retval = dict(
            [
                (item[0].lower(), [val.lower() for val in item[1]])
                for item in res[0][1].items()
            ]
        )
        print(retval)
        return retval

    def authenticate_user(self, user: str, password: str) -> bool:
        "Verify a user against the table"

        userobj = self.get_user(user, password)
        if not userobj:
            return False
        return True

    def authorize_user(self, user: str, authz_detail: BaseAuthorizationDetails) -> bool:
        return True


if __name__ == "__main__":
    d = LdapSource(
        "ldap_test",
        LDAPConfiguration(
            plugin_name="ldap_test",
            host_ip=IPv4Address("192.168.100.60"),
            port=389,
            dn_format="cn=%s,ou=people,dc=haqa,dc=net",
            attributes=["memberOf"],
            values=["CN=Users,DC=haqa,DC=net"],
        ),
    )
    d.authenticate_user("fred", "password1")
