from abc import ABC, abstractmethod
from typing import Any, Tuple

from structlog.stdlib import BoundLogger


class BasePacketHandlerException(Exception):
    pass


class BasePacketHandler(ABC):
    def __init__(self, logger: BoundLogger, mod_config: Any) -> None:
        self.logger: BoundLogger = logger
        self.mod_config: Any = mod_config

    @abstractmethod
    def handle_packet(self, packet_data: bytes, client_address: Tuple) -> Any:
        raise NotImplementedError("handle_packet method must be implemented")
