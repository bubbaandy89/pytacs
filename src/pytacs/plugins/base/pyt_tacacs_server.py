#!/usr/bin/python
"""
PyTACS TACACS+ listener and handler
"""

import logging
from ipaddress import IPv4Address, IPv6Address, ip_address
from socketserver import StreamRequestHandler, ThreadingTCPServer
from threading import Thread
from typing import Any, List, Optional, Tuple, Union

from structlog.stdlib import BoundLogger

from pytacs.plugins.base.packet_handler import BasePacketHandler, BasePacketHandlerException
from pytacs.plugins.base.pytacs_lib import PyTACSModule
from pytacs.structures.models.client import ClientConfiguration
from pytacs.structures.models.server import ServerConfiguration
from pytacs.structures.packets.packet import (
    TAC_PLUS_ACCT,
    TAC_PLUS_AUTHEN,
    TAC_PLUS_AUTHOR,
    TAC_PLUS_SINGLE_CONNECT_FLAG,
    Packet,
)


class InvalidPacketTypeException(BasePacketHandlerException):
    pass


class PacketTypeMismatchException(InvalidPacketTypeException):
    pass


class TACACSPlusPacketHandler(BasePacketHandler):
    def __init__(self, logger: BoundLogger, mod_config: ServerConfiguration) -> None:
        super().__init__(logger, mod_config)
        self.session: Optional[Any] = None

    def _find_client_by_ip(
        self, target_ip: Union[IPv4Address, IPv6Address]
    ) -> Optional[ClientConfiguration]:
        """
        Find a client dictionary by IP address from a list of client dictionaries.

        Args:
            target_ip: IP address to search for

        Returns:
            Matching dictionary or None if not found
        """
        return next(
            (client for client in self.mod_config.clients if client["ip_address"] == target_ip),
            None,
        )

    def _get_packet_type(self, decrypted_packet: Packet) -> Optional[Packet]:
        reply: Optional[Packet] = None
        if decrypted_packet.get_type() == TAC_PLUS_AUTHEN:
            reply = self.process_authn(decrypted_packet)
        elif decrypted_packet.get_type() == TAC_PLUS_AUTHOR:
            reply = self.process_authz(decrypted_packet)
        elif decrypted_packet.get_type() == TAC_PLUS_ACCT:
            reply = self.process_acct(decrypted_packet)
        else:
            self.logger.error(f"Bad packet type: {decrypted_packet._type}")

        return reply

    def handle_packet(self, packet_data: bytes, client_address: Tuple) -> Optional[bytes]:
        client_ip: Union[IPv4Address, IPv6Address] = ip_address(client_address[0])
        self.logger.debug(f"Received packet from {client_ip}")
        if client := self._find_client_by_ip(client_ip):
            self.logger.debug(f"Found client in config: {client}")
            secret: bytes = client.secret.get_secret_value().encode()
            decrypted_packet: Packet = Packet.decode(packet_data, secret)
            if decrypted_packet.get_seq_number() == 1:
                self.session = {}
                self.start: Packet = decrypted_packet
            else:
                if decrypted_packet.get_type() != self.start.get_type():
                    self.logger.error("Packet type mismatch")
                    raise PacketTypeMismatchException("Packet type mismatch")

            reply: Optional[Packet] = self._get_packet_type(decrypted_packet)
            if not reply:
                raise InvalidPacketTypeException("Invalid packet type")
            else:
                if reply.get_seq_number() < 3:
                    reply.set_flag(TAC_PLUS_SINGLE_CONNECT_FLAG)
                return reply.encode()
        return None

    def process_authn(self, packet: Packet) -> Packet:
        "Process an Authentication packet"
        reply: Packet = packet.reply()
        return reply

    def process_authz(self, packet: Packet) -> Packet:
        "Process an Authorization packet"
        reply: Packet = packet.reply()
        return reply

    def process_acct(self, packet: Packet) -> Packet:
        "Process an Authorization packet"
        reply: Packet = packet.reply()
        return reply


class TACACSPlusHandler(StreamRequestHandler):
    "Simple TACACS+ connection handler. Decode the packet and process"

    def handle(self):
        "Handle a tacacs packet"
        client = self.client_address[0]
        secret = self.server.clients.get(client, None)
        logging.debug("Entering packet loop")
        while 1:
            data = self.request.recv(4096)
            if not data:
                break
            decoded_packet: Packet = Packet.decode(data, secret)
            if decoded_packet.get_seq_number() == 1:
                self.session = {}
                self.start: Packet = decoded_packet
            else:
                if decoded_packet.get_type() != self.start.get_type():
                    logging.error("Packet type mismatch")
                    break
            if decoded_packet.get_type() == TAC_PLUS_AUTHEN:
                reply = self.process_authn(decoded_packet)
            elif decoded_packet.get_type() == TAC_PLUS_AUTHOR:
                reply = self.process_authz(decoded_packet)
            elif decoded_packet.get_type() == TAC_PLUS_ACCT:
                reply = self.process_acct(decoded_packet)
            else:
                logging.error(f"Bad packet type: {decoded_packet._type}")
                break
            if reply:
                if reply.get_seq_number() < 3:
                    reply.set_flag(TAC_PLUS_SINGLE_CONNECT_FLAG)
                self.request.send(reply.encode())
        self.session = None
        self.start = None
        logging.debug("Packet loop exited")
        self.request.shutdown(2)
        self.request.close()

    def process_authn(self, packet: Packet) -> Packet:
        "Process an Authentication packet"
        reply: Packet = packet.reply()
        return reply

    def process_authz(self, packet: Packet) -> Packet:
        "Process an Authorization packet"
        reply: Packet = packet.reply()
        return reply

    def process_acct(self, packet: Packet) -> Packet:
        "Process an Authorization packet"
        reply: Packet = packet.reply()
        return reply


class TACACSPlusListener(ThreadingTCPServer):
    "TCP Listener for PyTACS server"

    allow_reuse_address: bool = True

    def __init__(self, addr) -> None:
        "Initialize the socket, start the thread"
        super().__init__(addr, TACACSPlusHandler)


class PYTacsTACACSServer(PyTACSModule, Thread):

    __required__: List[str] = ["listening_address", "listening_port", "clients"]
    __registry__: str = "servers"

    def __init__(self, name: str, modconfig: ServerConfiguration, logger: BoundLogger) -> None:
        self.logger: BoundLogger = logger

        "Start the tacacs server and record it in the server list"
        self.running: bool = True
        super().__init__(
            name,
            modconfig,
        )
        Thread.__init__(
            self,
            name=f"PyTACS TACACS+ Listener ({name})",
        )
        self.listener: TACACSPlusListener = TACACSPlusListener(
            (self.modconfig.listening_address, self.modconfig.listening_port),
        )
        self.start()

    def stop(self) -> None:
        "Set the flag to stop the thread"
        self.logger.info(f"Stopping {self.getName()}")
        self.running = False

    def run(self) -> None:
        "Start listening"
        self.logger.info(f"Starting {self.getName()}")
        while self.running:
            self.listener.handle_request()

    def __reg_module__(self, globals, name) -> None:
        "Register this module and grab the secrets"
        super().__reg_module__(globals, name)
        clients = self.modconfig.clients
        self.logger.debug(f"Clients: {clients}")
        self.listener.clients = clients
