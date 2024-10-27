#!/usr/bin/env python
"""
PyTACS User Source Base Class
"""

from abc import abstractmethod
from typing import List

from pytacs.plugins.base.pytacs_lib import PyTACSModule
from pytacs.structures.models.authorization import BaseAuthorizationDetails


class UserSource(PyTACSModule):
    """
    Base defintion for a source of users for authentication and authorization
    """

    __required__: List[str] = []
    __registry__: str = "usersources"

    def __init__(self, name: str, modconfig) -> None:
        "Initialise the module and record this user source"
        PyTACSModule.__init__(self, name, modconfig)

    @abstractmethod
    def authenticate_user(self, user: str, password: str) -> bool:
        "Verify a user against the datasource"
        raise NotImplementedError()

    @abstractmethod
    def authorize_user(self, user: str, authz_detail: BaseAuthorizationDetails) -> bool:
        "Verify a user against the datasource"
        raise NotImplementedError()
