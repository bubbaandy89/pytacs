import logging
import struct
from hashlib import md5
from typing import Any, Generator, Literal, Union

import pytacs.structures.exceptions as exceptions

# Constants
TAC_PLUS_MAJOR_VER: Literal[12] = 0x0C
TAC_PLUS_MINOR_VER_DEFAULT: Literal[0] = 0x00
TAC_PLUS_MINOR_VER_ONE: Literal[1] = 0x01

TAC_PLUS_AUTHEN: Literal[1] = 0x01  # Authentication
TAC_PLUS_AUTHOR: Literal[2] = 0x02  # Authorization
TAC_PLUS_ACCT: Literal[3] = 0x03  # Accounting

TAC_PLUS_UNENCRYPTED_FLAG: Literal[1] = 0x01
TAC_PLUS_SINGLE_CONNECT_FLAG: Literal[4] = 0x04

# Authentication packet types
TAC_PLUS_AUTHEN_START: Literal[1] = 0x01
TAC_PLUS_AUTHEN_REPLY: Literal[2] = 0x02
TAC_PLUS_AUTHEN_CONTINUE: Literal[3] = 0x03

# Authentication types
TAC_PLUS_AUTHEN_LOGIN: Literal[1] = 0x01
TAC_PLUS_AUTHEN_CHPASS: Literal[2] = 0x02
TAC_PLUS_AUTHEN_SENDPASS: Literal[3] = 0x03  # Deprecated
TAC_PLUS_AUTHEN_SENDAUTH: Literal[4] = 0x04

# Privilege levels
TAC_PLUS_PRIV_LVL_MAX: Literal[15] = 0x0F
TAC_PLUS_PRIV_LVL_ROOT: Literal[15] = 0x0F
TAC_PLUS_PRIV_LVL_USER: Literal[1] = 0x01
TAC_PLUS_PRIV_LVL_MIN: Literal[0] = 0x00

# Authentication types
TAC_PLUS_AUTHEN_TYPE_ASCII: Literal[1] = 0x01
TAC_PLUS_AUTHEN_TYPE_PAP: Literal[2] = 0x02
TAC_PLUS_AUTHEN_TYPE_CHAP: Literal[3] = 0x03
TAC_PLUS_AUTHEN_TYPE_ARAP: Literal[4] = 0x04
TAC_PLUS_AUTHEN_TYPE_MSCHAP: Literal[5] = 0x05

# Authentication services
TAC_PLUS_AUTHEN_SVC_NONE: Literal[0] = 0x00
TAC_PLUS_AUTHEN_SVC_LOGIN: Literal[1] = 0x01
TAC_PLUS_AUTHEN_SVC_ENABLE: Literal[2] = 0x02
TAC_PLUS_AUTHEN_SVC_PPP: Literal[3] = 0x03
TAC_PLUS_AUTHEN_SVC_ARAP: Literal[4] = 0x04
TAC_PLUS_AUTHEN_SVC_PT: Literal[5] = 0x05
TAC_PLUS_AUTHEN_SVC_RCMD: Literal[6] = 0x06
TAC_PLUS_AUTHEN_SVC_X25: Literal[7] = 0x07
TAC_PLUS_AUTHEN_SVC_NASI: Literal[8] = 0x08
TAC_PLUS_AUTHEN_SVC_FWPROXY: Literal[9] = 0x09

# Authentication status
TAC_PLUS_AUTHEN_STATUS_PASS: Literal[1] = 0x01
TAC_PLUS_AUTHEN_STATUS_FAIL: Literal[2] = 0x02
TAC_PLUS_AUTHEN_STATUS_GETDATA: Literal[3] = 0x03


class Packet:
    """
    The TACACS+ packet header

    1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
    +----------------+----------------+----------------+----------------+
    |major  | minor  |                |                |                |
    |version| version|      type      |     seq_no     |   flags        |
    +----------------+----------------+----------------+----------------+
    |                                                                   |
    |                            session_id                             |
    +----------------+----------------+----------------+----------------+
    |                                                                   |
    |                              length                               |
    +----------------+----------------+----------------+----------------+
    """

    def __init__(self, session: int, secret: str) -> None:
        self._secret: str = secret
        self._packet: bytes = b""
        self._major: int = TAC_PLUS_MAJOR_VER
        self._minor: int = TAC_PLUS_MINOR_VER_DEFAULT
        self._type: int = 0
        self._seq_no: int = 0
        self._flags: int = 0
        self._session_id: int = session
        self._length: int = 0
        self._body: str = ""
        self._packstr: bytes = b"!BBBBII"

    def _pseudo_pad(self) -> Generator[int, Any, None]:
        """Generate the pseudo random pad for encryption/decryption"""
        logging.debug(f"_packet = {self._packet.decode()}")
        logging.debug(f"secret = {self._secret}")
        key: bytes = (
            self._packet[4:8]
            + self._secret.encode()
            + self._packet[:1]
            + self._packet[2:3]
        )
        while True:
            hash_value: bytes = md5(key).digest()
            yield from hash_value

    def _crypt(self, data: bytes) -> bytes:
        data_length: int = len(data)
        unhashed: bytes = (
            self._packet[4:8]
            + self._secret.encode()
            + self._packet[:1]
            + self._packet[2:3]
        )

        while len(pad) < data_length:
            hashed = md5(unhashed + hashed).digest()
            pad += hashed

        pad = pad[:data_length]
        pad = list(pad)

        return bytes(x ^ y for x, y in zip(data, pad))

    def __repr__(self) -> str:
        return f"<Packet: {self.__class__.__name__.split('.')[-1]}, Ver: {self._major}/{self._minor}>"

    def __str__(self) -> str:
        return (
            f"Packet:\t{self.__class__.__name__.split('.')[-1]}\n"
            f"Ver:\t{self._major}/{self._minor}\n"
            f"Type:\t{self._type}\n"
            f"Seq:\t{self._seq_no}\n"
            f"Flags:\t{self._flags}\n"
            f"Ses'n:\t{self._session_id}\n"
            f"Length:\t{self._length}\n"
            f"---------- BODY START\n"
            f"{self._body}\n"
            f"---------- BODY END\n"
        )

    @staticmethod
    def decode(
        packet_data: bytes, secret: str
    ) -> Union["Authentication", "Authorization", "Accounting"]:
        """Decode a packet off the wire and return an object"""
        for packet_item in packet_data:
            logging.info(f"Packet data {packet_item}")

        tactype: int = packet_data[1]
        if tactype == TAC_PLUS_AUTHEN:
            obj = Authentication()
        elif tactype == TAC_PLUS_AUTHOR:
            obj = Authorization()
        elif tactype == TAC_PLUS_ACCT:
            obj = Accounting()
        else:
            raise exceptions.PyTACSError("Invalid packet type received")

        obj._secret = secret
        obj._packet = packet_data
        obj._decode()
        return obj

    def _decode(self) -> None:
        """
        Decode the packet header. This also decrypts the body,
        this should therefore be called FIRST in subclasses.
        """
        self._major = (ver >> 4) & 0xF

    def encode(self) -> bytes:
        """
        Encode a packet ready for the wire. This also encrypts the body,
        this should therefore be called LAST in subclasses.
        Returns the completed packet.
        """
        self._packet += self._crypt(self._body)
        return self._packet

    def reply(self) -> "Packet":
        """
        Construct a reply packet by duplicating the header fields
        and then incrementing the sequence number field.
        This is done by encoding the existing packet, truncating to 8
        bytes, appending a length of zero (four zero bytes) then
        decoding it.
        """
        newpacket = Packet.decode(self.encode()[:8] + b"\0\0\0\0", self._secret)
        newpacket._seq_no += 1
        return newpacket

    def get_type(self) -> int:
        """Return the numeric type of this packet"""
        return self._type

    def get_session_id(self) -> int:
        """Return the session ID of this packet"""
        return self._session_id

    def set_seq_number(self, seq_no: int) -> None:
        """Set the sequence number"""
        self._seq_no = seq_no

    def get_seq_number(self) -> int:
        """Get the sequence number"""
        return self._seq_no

    def set_flag(self, flag: int) -> None:
        """Set the bit(s) for the passed flag(s)"""
        self._flags |= flag

    def reset_flag(self, flag: int) -> None:
        """Reset the bit(s) for the passed flag(s)"""
        self._flags &= ~flag & 255

    def get_flag(self, flag: int) -> bool:
        """Is the passed flag set?"""
        return (self._flags & flag) == flag
