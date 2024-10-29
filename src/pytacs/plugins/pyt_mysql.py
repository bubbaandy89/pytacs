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

from functools import cached_property
from typing import Any, List, Union

import mysql.connector
from mysql.connector.abstracts import MySQLConnectionAbstract
from mysql.connector.pooling import PooledMySQLConnection

from pytacs.plugins.base.user_source import UserSource
from pytacs.structures.models.authorization import BaseAuthorizationDetails
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
        "group_membership_column",
    ]

    def __init__(self, name: str, modconfig: MySQLConfiguration) -> None:
        "Prepare MySQL settings"
        super().__init__(name, modconfig)

    @cached_property
    def mysql_connection(self) -> Union[PooledMySQLConnection, MySQLConnectionAbstract]:
        return mysql.connector.connect(
            host=self.modconfig.host,
            user=self.modconfig.database_user_name,
            password=self.modconfig.database_user_password,
            database=self.modconfig.database_name,
        )

    def _get_user_mysql_query(self, user_name: str) -> str:
        table_name = self.modconfig.table_name
        user_column_name = self.modconfig.user_column_name
        password_column_name = self.modconfig.password_column_name
        group_membership_column_name = self.modconfig.group_membership_column_name

        query: str = (
            f"SELECT {user_column_name}, {password_column_name}, {group_membership_column_name} FROM {table_name} "
            f"WHERE {user_column_name} CONTAINS {user_name}"
        )
        return query

    def get_mysql_user(self, user_name: str) -> Any:
        """Get a user from the MySQL table"""
        cursor = self.mysql_connection.cursor()
        query: str = self._get_user_mysql_query(user_name)
        cursor.execute(query)
        result = cursor.fetchone()
        return result

    def authenticate_user(self, user: str, password: str) -> bool:
        "Verify a user against the MySQL table"
        (_, stored_user_password, _) = self.get_mysql_user(user)
        if stored_user_password == password:
            return True
        else:
            return False

    def authorize_user(self, user: str, authz_detail: BaseAuthorizationDetails) -> bool:
        "Verify a user against the MySQL table"
        (_, _, stored_user_group_membership) = self.get_mysql_user(user)
        return False
