#!/usr/bin/python
"""
PyTACS MySQL User Source

Must have the following options defined
    host
    user
    pass
    db
    table
    user_column
    pass_column
"""

from typing import List

from pytacs import user_source


class pyt_mysql(user_source.UserSource):
    "A user source based on a MySQL table"

    __required__: List[str] = [
        "host",
        "user",
        "pass",
        "db",
        "table",
        "user_column",
        "pass_column",
    ]

    def __init__(self, name, modconfig):
        "Prepare MySQL settings"
        user_source.UserSource.__init__(self, name, modconfig)

    def checkUser(self, user, password):
        "Verify a user against the MySQL table"
        return False
