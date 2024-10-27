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

from pytacs.plugins.base.user_source import UserSource
from pytacs.structures.models.configurations.plugins.mysql import MySQLConfiguration


class PYTacsMySQL(UserSource):
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

    def __init__(self, name: str, modconfig: MySQLConfiguration) -> None:
        "Prepare MySQL settings"
        super().__init__(name, modconfig)

    def check_user(self, user, password):
        "Verify a user against the MySQL table"
        return False
