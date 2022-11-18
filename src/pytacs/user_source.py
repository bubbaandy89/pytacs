#!/usr/bin/env python
"""
PyTACS User Source Base Class
"""

from typing import List

import pytacs.pytacs_lib as pytacs_lib


class UserSource(pytacs_lib.PyTACSModule):
    "A source of users for authentication"

    __required__: List[str] = []
    __registry__: str = "usersources"

    def __init__(self, name, modconfig):
        "Initialise the module and record this user source"
        pytacs_lib.PyTACSModule.__init__(self, name, modconfig)

    def check_user(self, user, password) -> bool:
        "Verify a user against the datasource"
        return False
