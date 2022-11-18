#!/usr/bin/python
"""
PyTACS TACACS+ listener and handler
"""

import logging
import socketserver
import threading
from typing import List, Union

from pytacs import packet, pytacs_lib


class TACACSPlusHandler(socketserver.StreamRequestHandler):
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
            decoded_packet: Union[
                packet.Authentication, packet.Authorization, packet.Accounting
            ] = packet.Packet.decode(data, secret)
            if decoded_packet.get_seq_number() == 1:
                self.session = {}
                self.start = decoded_packet
            else:
                if decoded_packet.get_type() != self.start.get_type():
                    logging.error("Packet type mismatch")
                    break
            if decoded_packet.get_type() == packet.TAC_PLUS_AUTHEN:
                reply = self.process_authn(decoded_packet)
            elif decoded_packet.get_type() == packet.TAC_PLUS_AUTHOR:
                reply = self.process_authz(decoded_packet)
            elif decoded_packet.get_type() == packet.TAC_PLUS_ACCT:
                reply = self.process_acct(decoded_packet)
            else:
                logging.error(f"Bad packet type: {decoded_packet._type}")
                break
            if reply.get_seq_number() < 3:
                reply.set_flag(packet.TAC_PLUS_SINGLE_CONNECT_FLAG)
            self.request.send(reply.encode())
        self.session = None
        self.start = None
        logging.debug("Packet loop exited")
        self.request.shutdown(2)
        self.request.close()

    def process_authn(self, packet):
        "Process an Authorization packet"
        reply = packet.reply()
        return reply

    def process_authz(self, packet):
        "Process an Authorization packet"
        pass

    def process_acct(self, packet):
        "Process an Authorization packet"
        pass


class TACACSPlusListener(socketserver.ThreadingTCPServer):
    "TCP Listener for PyTACS server"

    allow_reuse_address: bool = 1

    def __init__(self, addr):
        "Initialize the socket, start the thread"
        socketserver.ThreadingTCPServer.__init__(self, addr, TACACSPlusHandler)


class pyt_tacacs_server(pytacs_lib.PyTACSModule, threading.Thread):

    __required__: List[str] = ["address", "port", "clients"]
    __registry__: str = "servers"

    def __init__(self, name, modconfig):
        "Start the tacacs server and record it in the server list"
        self.running: bool = True
        pytacs_lib.PyTACSModule.__init__(
            self,
            name,
            modconfig,
        )
        threading.Thread.__init__(
            self,
            name="PyTACS TACACS+ Listener (%s)" % (name,),
        )
        self.listener: TACACSPlusListener = TACACSPlusListener(
            (self.modconfig["address"], int(self.modconfig["port"])),
        )
        self.start()

    def stop(self):
        "Set the flag to stop the thread"
        self.running = False

    def run(self):
        "Start listening"
        logging.info("Starting %s" % self.getName())
        while self.running:
            self.listener.handle_request()

    def __reg_module__(self, globals, name):
        "Register this module and grab the secrets"
        pytacs_lib.PyTACSModule.__reg_module__(self, globals, name)
        clients = self.modconfig["clients"]
        self.listener.clients = globals["config"][clients]
