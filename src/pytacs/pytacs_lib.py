#!/usr/bin/env python
"""
PyTACS Base Module Class
"""
from typing import List, Optional

import pytacs.exceptions as exceptions


class PyTACSModule(object):
    "A basic module with required config entry support"

    __required__: List[str] = []
    __registry__: Optional[str] = None

    def __init__(self, name, modconfig):
        "Prepare whatever is needed"
        self.modconfig = modconfig
        for key in self.__required__:
            if key not in self.modconfig:
                raise exceptions.ConfigurationError(
                    f"Required option '{key}' "
                    "missing [{name}:{self.__class__.__name__.split('.')[-1]}]"
                )

    def __reg_module__(self, globals, name):
        "Register this module in the appropriate registry"
        globals[self.__registry__][name] = self
