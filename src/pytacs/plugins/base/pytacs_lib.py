#!/usr/bin/env python
"""
PyTACS Base Module Class
"""

from typing import Any, List

import pytacs.structures.exceptions as exceptions


class PyTACSModule:
    "A basic module with required config entry support"

    __required__: List[str] = []
    __registry__: str = ""

    def __init__(self, name: str, modconfig: Any) -> None:
        "Prepare whatever is needed"
        self.modconfig = modconfig
        for key in self.__required__:
            if key not in self.modconfig.model_dump():
                raise exceptions.ConfigurationError(
                    f"Required option '{key}' "
                    f"missing [{name}:{self.__class__.__name__.split('.')[-1]}]"
                )

    def __reg_module__(self, globals, name) -> None:
        "Register this module in the appropriate registry"
        globals[self.__registry__][name] = self
