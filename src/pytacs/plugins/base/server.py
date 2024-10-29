import socket
from ipaddress import IPv4Address, IPv6Address
from threading import Thread
from typing import Optional, Tuple, Type, Union

import structlog
from structlog.stdlib import BoundLogger

from pytacs.plugins.base.packet_handler import BasePacketHandler, BasePacketHandlerException
from pytacs.structures.models.server import ServerConfiguration


class MultiThreadedTCPListener:
    """
    Potential alternative for listener, needs some work.
    """

    def __init__(
        self,
        mod_config: ServerConfiguration,
        packet_handler_class: Type[BasePacketHandler],
        logger: Optional[BoundLogger] = None,
    ) -> None:
        self.receive_buffer_size: int = 4096
        self.mod_config: ServerConfiguration = mod_config
        self.listen_host: Union[IPv4Address, IPv6Address] = self.mod_config.listening_address
        self.listen_port: int = self.mod_config.listening_port
        self.packet_handler_class: Type[BasePacketHandler] = packet_handler_class
        self.logger: BoundLogger = logger or structlog.get_logger(__name__)
        self.socket: Optional[socket.socket] = None
        self.running: bool = False

    def start_server(self) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.listen_host, self.listen_port))
        self.socket.listen(5)
        self.running = True

        self.logger.info(f"Server started on {self.listen_host}:{self.listen_port}")

        self.server_listen()

    def server_listen(self) -> None:

        while self.running:
            try:
                client_socket, client_address = self.socket.accept()
                self.logger.info(f"New connection from {client_address}")
                client_thread = Thread(
                    target=self.handle_client, args=(client_socket, client_address)
                )
                client_thread.start()
            except Exception as e:
                self.logger.error(f"Error accepting connection: {e}")

    def stop(self) -> None:
        self.running = False
        if self.socket:
            self.socket.close()
        self.logger.info("Server stopped")

    def packet_handler(self) -> BasePacketHandler:
        packet_handler = self.packet_handler_class(logger=self.logger, mod_config=self.mod_config)
        return packet_handler

    def handle_client(self, client_socket: socket.socket, client_address: Tuple) -> None:
        """
        client_address info is a pair (hostaddr, port)
        """
        try:
            while self.running:
                data: bytes = client_socket.recv(self.receive_buffer_size)
                if not data:
                    self.logger.info(f"Client {client_address} disconnected")
                    continue

                try:
                    # Parse the packet using the provided handler
                    reply = self.packet_handler.handle_packet(data, client_address=client_address)
                except BasePacketHandlerException:
                    self.logger.exception(f"Error handling packet from {client_address}")
                    break

                # Here you can do something with the result if needed
                self.logger.debug(
                    f"Processed packet from {client_address} and generated reply: {reply}"
                )

                client_socket.sendall(reply)

                self.logger.debug(f"Sent reply to {client_address}")

        except Exception as e:
            self.logger.error(f"Error handling client {client_address}: {e}")
        finally:
            client_socket.close()
            self.logger.info(f"Connection closed for {client_address}")
