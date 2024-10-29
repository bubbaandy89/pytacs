#!/usr/bin/python
"""
PyTACS TACACS+ listener and handler
"""

import logging
import socket
import threading
from ipaddress import IPv4Address, IPv6Address, ip_address
from socketserver import StreamRequestHandler, ThreadingTCPServer
from threading import Thread
from typing import Any, Callable, List, Optional, Union

from pytacs.plugins.base.pytacs_lib import PyTACSModule
from pytacs.structures.models.server import ServerConfiguration
from pytacs.structures.packets.packet import (
    TAC_PLUS_ACCT,
    TAC_PLUS_AUTHEN,
    TAC_PLUS_AUTHOR,
    TAC_PLUS_SINGLE_CONNECT_FLAG,
    Packet,
)


class MultiThreadedTCPListener:
    """
    Potential alternative for listener, needs some work.
    """

    def __init__(
        self,
        listen_ip: Union[IPv4Address, IPv6Address],
        listen_port: int,
        packet_handler: Callable[[bytes], Any],
    ) -> None:
        self.listen_host: Union[IPv4Address, IPv6Address] = listen_ip
        self.listen_port: int = listen_port
        self.packet_handler = packet_handler
        self.socket: Optional[socket.socket] = None
        self.running: bool = False

    def start_server(self) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.listen_host, self.listen_port))
        self.socket.listen(5)
        self.running = True

        logging.info(f"Server started on {self.listen_host}:{self.listen_port}")

        while self.running:
            try:
                client_socket, nas_address = self.socket.accept()
                logging.info(f"New connection from {nas_address}")
                client_thread = threading.Thread(
                    target=self.handle_client, args=(client_socket, nas_address)
                )
                client_thread.start()
            except Exception as e:
                logging.error(f"Error accepting connection: {e}")

    def stop(self):
        self.running = False
        if self.socket:
            self.socket.close()
        logging.info("Server stopped")

    def handle_client(self, client_socket: socket.socket, address: tuple):
        try:
            while self.running:
                data = client_socket.recv(4096)
                if not data:
                    break

                # Parse the packet using the provided handler
                result = self.packet_handler(data)

                # Here you can do something with the result if needed
                logging.info(f"Processed packet from {address}: {result}")

        except Exception as e:
            logging.error(f"Error handling client {address}: {e}")
        finally:
            client_socket.close()
            logging.info(f"Connection closed for {address}")


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

    def __init__(self, name, modconfig: ServerConfiguration) -> None:
        "Start the tacacs server and record it in the server list"
        self.running: bool = True
        super().__init__(
            name,
            modconfig,
        )
        threading.Thread.__init__(
            self,
            name="PyTACS TACACS+ Listener (%s)" % (name,),
        )
        self.listener: TACACSPlusListener = TACACSPlusListener(
            (self.modconfig.listening_address, self.modconfig.listening_port),
        )
        self.start()

    def stop(self) -> None:
        "Set the flag to stop the thread"
        self.running = False

    def run(self) -> None:
        "Start listening"
        logging.info(f"Starting {self.getName()}")
        while self.running:
            self.listener.handle_request()

    def __reg_module__(self, globals, name) -> None:
        "Register this module and grab the secrets"
        super().__reg_module__(globals, name)
        clients = self.modconfig.clients
        self.listener.clients = clients
