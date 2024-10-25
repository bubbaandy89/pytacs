"""
PyTACS LDAP User Source

Must have the following options defined
    host	The hostname or ip address of the LDAP server
    port	The port number the LDAP server is listening on
    dnfmt	An LDAP DN with the token %s where the username should be inserted
"""

from typing import Dict, List, Optional

import ldap

from pytacs.user_source import UserSource


class LdapSource(UserSource):
    "A user source based on an LDAP directory"

    __required__: List[str] = ["host", "port", "dnfmt"]

    def __init__(self, name, modconfig):
        "Prepare LDAP settings"
        UserSource.__init__(self, name, modconfig)

    def getUser(self, user, password) -> Optional[Dict[str, List[str]]]:
        " "
        conn = ldap.open(self.modconfig["host"], int(self.modconfig["port"]))
        try:
            conn.simple_bind_s(user, password)
        except Exception:
            return None
        res = conn.search_s(user, ldap.SCOPE_BASE, "objectClass=*")
        retval = dict(
            [
                (item[0].lower(), [val.lower() for val in item[1]])
                for item in res[0][1].items()
            ]
        )
        print(retval)
        return retval

    def check_user(self, user, password):
        "Verify a user against the table"
        bind_dn = self.modconfig["dnfmt"] % user
        userobj = self.getUser(bind_dn, password)
        if not userobj:
            return False
        return True


if __name__ == "__main__":
    d = LdapSource(
        {
            "host": "192.168.100.60",
            "port": "389",
            "dnfmt": "cn=%s,ou=people,dc=haqa,dc=net",
        }
    )
    d.check_user("fred", "password1")
