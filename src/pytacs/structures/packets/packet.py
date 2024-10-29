import logging
import struct
from enum import IntEnum
from hashlib import md5
from typing import Any, Dict, Generator, List, Literal, Optional

import pytacs.structures.exceptions as exceptions
from pytacs.structures.exceptions import PyTACSError

TAC_PLUS_MAJOR_VER: Literal[12] = 0x0C

TAC_PLUS_MINOR_VER_DEFAULT: Literal[0] = 0x00
TAC_PLUS_MINOR_VER_ONE: Literal[1] = 0x01

TAC_PLUS_AUTHEN: Literal[1] = 0x01  # Authentication
TAC_PLUS_AUTHOR: Literal[2] = 0x02  # Authorization
TAC_PLUS_ACCT: Literal[3] = 0x03  # Accounting

TAC_PLUS_UNENCRYPTED_FLAG: Literal[1] = 0x01
TAC_PLUS_SINGLE_CONNECT_FLAG: Literal[4] = 0x04

TAC_PLUS_AUTHEN_START: Literal[1] = 0x01  # \
TAC_PLUS_AUTHEN_REPLY: Literal[2] = 0x02  # |-- Unofficial flags used by PyTACS
TAC_PLUS_AUTHEN_CONTINUE: Literal[3] = 0x03  # /

TAC_PLUS_AUTHEN_LOGIN: Literal[1] = 0x01
TAC_PLUS_AUTHEN_CHPASS: Literal[2] = 0x02
TAC_PLUS_AUTHEN_SENDPASS: Literal[3] = 0x03  # Deprecated
TAC_PLUS_AUTHEN_SENDAUTH: Literal[4] = 0x04

TAC_PLUS_PRIV_LVL_MAX: Literal[15] = 0x0F
TAC_PLUS_PRIV_LVL_ROOT: Literal[15] = 0x0F
TAC_PLUS_PRIV_LVL_USER: Literal[1] = 0x01
TAC_PLUS_PRIV_LVL_MIN: Literal[0] = 0x00

TAC_PLUS_AUTHEN_TYPE_ASCII: Literal[1] = 0x01
TAC_PLUS_AUTHEN_TYPE_PAP: Literal[2] = 0x02
TAC_PLUS_AUTHEN_TYPE_CHAP: Literal[3] = 0x03
TAC_PLUS_AUTHEN_TYPE_ARAP: Literal[4] = 0x04
TAC_PLUS_AUTHEN_TYPE_MSCHAP: Literal[5] = 0x05

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

TAC_PLUS_AUTHEN_STATUS_PASS: Literal[1] = 0x01
TAC_PLUS_AUTHEN_STATUS_FAIL: Literal[2] = 0x02
TAC_PLUS_AUTHEN_STATUS_GETDATA: Literal[3] = 0x03


class AuthenMethod(IntEnum):
    NOT_SET = 0x00
    NONE = 0x01
    KRB5 = 0x02
    LINE = 0x03
    ENABLE = 0x04
    LOCAL = 0x05
    TACACSPLUS = 0x06
    GUEST = 0x08
    RADIUS = 0x10
    KRB4 = 0x11
    RCMD = 0x20


class AuthStatus(IntEnum):
    PASS_ADD = 0x01  # Authorization permitted with additional attributes
    PASS = 0x02  # Authorization permitted
    FAIL = 0x10  # Authorization failed
    ERROR = 0x11  # Authorization error occurred
    FOLLOW = 0x21  # Follow instructions in server response


class AccountingFlags(IntEnum):
    MORE = 0x01  # deprecated
    START = 0x02  # Start record
    STOP = 0x04  # Stop record
    WATCHDOG = 0x08  # Update record


class AccountingStatus(IntEnum):
    SUCCESS = 0x01  # Accounting successful
    ERROR = 0x02  # Accounting error
    FOLLOW = 0x21  # Follow instructions in response


class Packet:
    """The TACACS+ packet header

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

    _secret: bytes = b""  # The secret for this connection
    _packet: bytes = b""
    _major: int = TAC_PLUS_MAJOR_VER
    _minor: int = TAC_PLUS_MINOR_VER_DEFAULT
    _type: int = 0
    _seq_no: int = 0
    _flags: int = 0
    _session_id: int = 0
    _length: int = 0
    _body: bytes = b""
    _packstr: bytes = b"!BBBBII"

    def __init__(self, session_id: Optional[int], secret: Optional[bytes]) -> None:
        "Constructor"
        self._session_id = session_id or 0
        self._secret = secret or b""

    def __pseudo_pad(self) -> Generator[int, Any, None]:
        "Generate the pseudo random pad for encryption/decryption"
        logging.debug(f"_packet = {self._packet.decode()}")
        logging.debug(f"secret = {self._secret.decode()}")
        key: bytes = self._packet[4:8] + self._secret + self._packet[:1] + self._packet[2:3]
        while 1:
            hash: bytes = md5(key).digest()
            for char in hash:
                yield char

    def __crypt(self, data: bytes) -> bytes:
        if self._flags & TAC_PLUS_UNENCRYPTED_FLAG or self._secret is None:
            return data
        data_length: int = len(data)
        unhashed: bytes = self._packet[4:8] + self._secret + self._packet[:1] + self._packet[2:3]
        pad = hashed = md5(unhashed).digest()

        if len(pad) < data_length:
            # remake hash, appending it to pad until pad >= header.length
            while True:
                hashed = md5(unhashed + hashed).digest()
                pad += hashed
                if len(pad) >= data_length:
                    break

        pad = pad[0:(data_length)]
        pad_list = list(struct.unpack("B" * len(pad), pad))

        packet_body = []
        for x in struct.unpack("B" * data_length, data):
            packet_body.append(x ^ pad_list.pop(0))

        return struct.pack("B" * len(packet_body), *packet_body)

    def __repr__(self) -> str:
        "Return a short version of the packet type"
        return "<Packet: %s, Ver: %s/%s>" % (
            self.__class__.__name__.split(".")[-1],
            self._major,
            self._minor,
        )

    def __str__(self) -> str:
        "Turn the packet into a usable string"
        return (
            f"Packet:\t{self.__class__.__name__.split('.')[-1]}\n"
            f"Ver:\t{self._major}/{self._minor}\n"
            f"Type:\t{self._type}\n"
            f"Seq:\t{self._seq_no}\n"
            f"Flags:\t{self._flags}\n"
            f"Ses'n:\t{self._session_id}\n"
            f"Length:\t{self._length}\n"
            f"---------- BODY START\n"
            f"{self._body.decode()}\n"
            f"---------- BODY END\n"
        )

    @staticmethod
    def decode(packet_data: bytes, secret: bytes) -> "Packet":
        "Decode a packet off the wire and return an object"
        for packet_item in packet_data:
            logging.info(f"Packet data {packet_item}")
        tactype: int = packet_data[1]
        obj: Packet
        if tactype == TAC_PLUS_AUTHEN:
            obj = Authentication()
        elif tactype == TAC_PLUS_AUTHOR:
            obj = Authorization()
        elif tactype == TAC_PLUS_ACCT:
            obj = Accounting()
        else:
            raise PyTACSError("Invalid packet type received")
        obj._secret = secret
        obj._packet = packet_data
        obj._decode()
        return obj

    def _decode(self):
        """Decode the packet header. This also decrypts the body,
        this should therfore be called FIRST in subclasses."""
        (
            ver,
            self._type,
            self._seq_no,
            self._flags,
            self._session_id,
            self._length,
        ) = struct.unpack(self._packstr, self._packet[:12])
        self._major = (ver >> 4) & 0xF
        self._minor = ver & 0xF
        self._body = self.__crypt(self._packet[12:])

    def encode(self) -> bytes:
        """Encode a packet ready for the wire. This also encrypts the body,
        this should therefore be called LAST in subclasses.
        Returns the completed packet."""
        self._length = len(self._body)
        self._packet = struct.pack(
            self._packstr,
            ((self._major & 0xF) << 4) | (self._minor & 0xF),
            self._type,
            self._seq_no,
            self._flags,
            self._session_id,
            self._length,
        )
        self._packet = self._packet + self.__crypt(self._body)
        return self._packet

    def reply(self) -> "Packet":
        """Construct a reply packet by duplicating the header fields
        and then incrementing the sequence number field.
        This is done by encoding the existing packet, tuncating to 8
        bytes, appending a length of zero (four zero bytes) then
        decoding it."""
        newpacket: Packet = Packet.decode(self.encode()[:8] + "\0\0\0\0".encode(), self._secret)
        newpacket._seq_no += 1
        return newpacket

    def get_type(self) -> int:
        "Return the numeric type of this packet"
        return self._type

    def get_session_id(self) -> int:
        "Return the session ID of this packet"
        return self._session_id

    def set_seq_number(self, seq_no: int) -> None:
        "Set the sequence number"
        self._seq_no = seq_no

    def get_seq_number(self) -> int:
        "Get the sequence number"
        return self._seq_no

    def reset_flag(self, flag: int) -> None:
        "Reset the bit(s) for the passed flag(s)"
        self._flags &= ~flag & 255

    def get_flag(self, flag: int) -> bool:
        "Is the passed flag set?"
        return (self._flags & flag) == flag


# }}}


# {{{ class Authentication
class Authentication(Packet):
    """The authentication packet bodies

    The authentication START packet body

          1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8

       +----------------+----------------+----------------+----------------+
       |    action      |    priv_lvl    |  authen_type   |     service    |
       +----------------+----------------+----------------+----------------+
       |    user len    |    port len    |  rem_addr len  |    data len    |
       +----------------+----------------+----------------+----------------+
       |    user ...
       +----------------+----------------+----------------+----------------+
       |    port ...
       +----------------+----------------+----------------+----------------+
       |    rem_addr ...
       +----------------+----------------+----------------+----------------+
       |    data...
       +----------------+----------------+----------------+----------------+

    The authentication REPLY packet body

          1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8

       +----------------+----------------+----------------+----------------+
       |     status     |      flags     |        server_msg len           |
       +----------------+----------------+----------------+----------------+
       |           data len              |        server_msg ...
       +----------------+----------------+----------------+----------------+
       |           data ...
       +----------------+----------------+

    The authentication CONTINUE packet body

          1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8

       +----------------+----------------+----------------+----------------+
       |          user_msg len           |            data len             |
       +----------------+----------------+----------------+----------------+
       |     flags      |  user_msg ...
       +----------------+----------------+----------------+----------------+
       |    data ...
       +----------------+"""

    _startstr: bytes = b"!BBBBBBBB"
    _replystr: bytes = b"!BBHH"
    _continuestr: bytes = b"!HH"

    def __init__(self, session_id: Optional[int] = None, secret: Optional[bytes] = None) -> None:
        "Initialise this authentication packet"
        super().__init__(session_id=session_id, secret=secret)
        self._type = TAC_PLUS_AUTHEN
        self._subtype: int = TAC_PLUS_AUTHEN_START
        self._fields: Dict[str, Any] = {}

    def _decode(self) -> None:
        "Decode the packet header and the authentication body"
        super()._decode()
        if self._seq_no == 1:
            self._subtype = TAC_PLUS_AUTHEN_START
        elif (int(self._seq_no / 2) * 2) != self._seq_no:
            self._subtype = TAC_PLUS_AUTHEN_REPLY
        else:
            self._subtype = TAC_PLUS_AUTHEN_CONTINUE

    def encode(self) -> bytes:
        "Encode a packet ready for the wire. Returns the completed packet."
        if self._subtype == TAC_PLUS_AUTHEN_START:
            self._body = (
                struct.pack(
                    self._startstr,
                    self.get_field("action", 0),
                    self.get_field("priv_lvl", 0),
                    self.get_field("authen_type", 0),
                    self.get_field("service", 0),
                    len(self.get_field("user", "")),
                    len(self.get_field("port", "")),
                    len(self.get_field("rem_addr", "")),
                    len(self.get_field("data", "")),
                )
                + self.get_field("user", "").encode()
                + self.get_field("port", "").encode()
                + self.get_field("rem_addr", "").encode()
                + self.get_field("data", "").encode()
            )
        elif self._subtype == TAC_PLUS_AUTHEN_REPLY:
            self._body = (
                struct.pack(
                    self._replystr,
                    self.get_field("status", 0),
                    self.get_field("flags", 0),
                    len(self.get_field("server_msg", "")),
                    len(self.get_field("data", "")),
                )
                + self.get_field("server_msg", "").encode()
                + self.get_field("data", "").encode()
            )
        elif self._subtype == TAC_PLUS_AUTHEN_CONTINUE:
            self._body = (
                struct.pack(
                    self._continuestr,
                    len(self.get_field("user_msg", "")),
                    len(self.get_field("data", "")),
                )
                + self.get_field("user_msg", "").encode()
                + self.get_field("data", "").encode()
            )
        else:
            raise exceptions.PyTACSError("Invalid packet sub-type")
        return Packet.encode(self)

    def set_field(self, field: str, value: Any) -> None:
        "Set a field value"
        self._fields[field] = value

    def get_field(self, field: str, default: Optional[Any] = None) -> Any:
        "Get a field"
        return self._fields.get(field, default)


class Authorization(Packet):
    """
       11.  Authorization

       TACACS+ authorization is an extensible way of providing remote

       authorization services.  An authorization session is defined as a
       single pair of messages, a REQUEST followed by a RESPONSE.

       The authorization REQUEST message contains a fixed set of fields that
       describe the authenticity of the user or process, and a variable set
       of arguments that describes the services and options for which
       authorization is requested.

       The RESPONSE contains a variable set of response arguments
       (attribute-value pairs) which can restrict or modify the clients
       actions.

       The arguments in both a REQUEST and a RESPONSE can be specified as
       either mandatory or optional. An optional argument is one that may or
       may not be used, modified or even understood by the recipient.

       A mandatory argument MUST be both understood and used. This allows
       for extending the attribute list while providing secure backwards
       compatibility.

       11.1.  The authorization REQUEST packet body



             1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8

          +----------------+----------------+----------------+----------------+
          |  authen_method |    priv_lvl    |  authen_type   | authen_service |
          +----------------+----------------+----------------+----------------+
          |    user len    |    port len    |  rem_addr len  |    arg_cnt     |
          +----------------+----------------+----------------+----------------+
          |   arg 1 len    |   arg 2 len    |      ...       |   arg N len    |
          +----------------+----------------+----------------+----------------+
          |   user ...
          +----------------+----------------+----------------+----------------+
          |   port ...
          +----------------+----------------+----------------+----------------+
          |   rem_addr ...
          +----------------+----------------+----------------+----------------+
          |   arg 1 ...
          +----------------+----------------+----------------+----------------+
          |   arg 2 ...
          +----------------+----------------+----------------+----------------+
          |   ...
          +----------------+----------------+----------------+----------------+
          |   arg N ...
          +----------------+----------------+----------------+----------------+


    authen_method

       This indicates the authentication method used by the client to
       acquire the user information.

       TAC_PLUS_AUTHEN_METH_NOT_SET    := 0x00

       TAC_PLUS_AUTHEN_METH_NONE       := 0x01

       TAC_PLUS_AUTHEN_METH_KRB5       := 0x02

       TAC_PLUS_AUTHEN_METH_LINE       := 0x03

       TAC_PLUS_AUTHEN_METH_ENABLE     := 0x04

       TAC_PLUS_AUTHEN_METH_LOCAL      := 0x05

       TAC_PLUS_AUTHEN_METH_TACACSPLUS := 0x06

       TAC_PLUS_AUTHEN_METH_GUEST      := 0x08

       TAC_PLUS_AUTHEN_METH_RADIUS     := 0x10

       TAC_PLUS_AUTHEN_METH_KRB4       := 0x11

       TAC_PLUS_AUTHEN_METH_RCMD       := 0x20


       KRB5 and KRB4 are kerberos version 5 and 4. LINE refers to a fixed
       password associated with the line used to gain access. LOCAL is a NAS
       local user database. ENABLE is a command that authenticates in order
       to grant new privileges. TACACSPLUS is, of course, TACACS+. GUEST is
       an unqualified guest authentication, such as an ARAP guest login.
       RADIUS is the Radius authentication protocol. RCMD refers to authen-
       tication provided via the R-command protocols from Berkeley Unix.
       (One should be aware of the security limitations to R-command authen-
       tication.)

    priv_lvl

       This field matches the priv_lvl field in the authentication section
       above. It indicates the users current privilege level.

    authen_type

       This field matches the authen_type field in the authentication sec-
       tion above. It indicates the type of authentication that was per-
       formed.

    authen_service

       This field matches the service field in the authentication section
       above. It indicates the service through which the user authenticated.

    user

       This field contains the user's account name.

    port

       This field matches the port field in the authentication section
       above.

    rem_addr

       This field matches the rem_addr field in the authentication section
       above.

    arg_cnt

       The number of authorization arguments to follow

    arg

       An attribute-value pair that describes the command to be performed.
       (see below)

       The authorization arguments in both the REQUEST and the RESPONSE are
       attribute-value pairs. The attribute and the value are in a single
       ascii string and are separated by either a "=" (0X3D) or a "*"
       (0X2A). The equals sign indicates a mandatory argument. The asterisk
       indicates an optional one.

       Optional arguments are ones that may be disregarded by either client
       or daemon. Mandatory arguments require that the receiving side under-
       stands the attribute and will act on it. If the client receives a
       mandatory argument that it cannot oblige or does not understand, it
       MUST consider the authorization to have failed. It is legal to send
       an attribute-value pair with a NULL (zero length) value.

       Attribute-value strings are not NULL terminated, rather their length
       value indicates their end. The maximum length of an attribute-value
       string is 255 characters. The following attributes are defined:



       12.  Table 1: Attribute-value Pairs


    service

       The primary service. Specifying a service attribute indicates that
       this is a request for authorization or accounting of that service.
       Current values are "slip", "ppp", "arap", "shell", "tty-daemon",
       "connection", "system" and "firewall". This attribute MUST always be
       included.

    protocol

       a protocol that is a subset of a service. An example would be any PPP
       NCP. Currently known values are "lcp", "ip", "ipx", "atalk", "vines",
       "lat", "xremote", "tn3270", "telnet", "rlogin", "pad", "vpdn", "ftp",
       "http", "deccp", "osicp" and "unknown".

    cmd

       a shell (exec) command. This indicates the command name for a shell
       command that is to be run. This attribute MUST be specified if ser-
       vice equals "shell". A NULL value indicates that the shell itself is
       being referred to.

    cmd-arg

       an argument to a shell (exec) command. This indicates an argument for
       the shell command that is to be run. Multiple cmd-arg attributes may
       be specified, and they are order dependent.

    acl

       ASCII number representing a connection access list. Used only when
       service=shell and cmd=NULL

    inacl

       ASCII identifier for an interface input access list.

    outacl

       ASCII identifier for an interface output access list.

    zonelist

       A numeric zonelist value. (Applicable to AppleTalk only).

    addr

       a network address

    addr-pool

       The identifier of an address pool from which the NAS should assign an
       address.

    routing

       A boolean. Specifies whether routing information is to be propagated
       to, and accepted from this interface.

    route

       Indicates a route that is to be applied to this interface. Values
       MUST be of the form "<dst_address> <mask> [<routing_addr>]". If a
       <routing_addr> is not specified, the resulting route should be via
       the requesting peer.

    timeout

       an absolute timer for the connection (in minutes). A value of zero
       indicates no timeout.

    idletime

       an idle-timeout for the connection (in minutes). A value of zero
       indicates no timeout.

    autocmd

       an auto-command to run. Used only when service=shell and cmd=NULL

    noescape

       Boolean. Prevents user from using an escape character. Used only when
       service=shell and cmd=NULL

    nohangup

       Boolean. Do no disconnect after an automatic command. Used only when
       service=shell and cmd=NULL

    priv_lvl

       privilege level to be assigned.

    remote_user

       remote userid (authen_method must have the value
       TAC_PLUS_AUTHEN_METH_RCMD)

    remote_host

       remote host (authen_method must have the value
       TAC_PLUS_AUTHEN_METH_RCMD)

    callback-dialstring

       Indicates that callback should be done. Value is NULL, or a dial-
       string. A NULL value indicates that the service MAY choose to get the
       dialstring through other means.

    callback-line

       The line number to use for a callback.

    callback-rotary

       The rotary number to use for a callback.

    nocallback-verify

       Do not require authentication after callback.


    For all boolean attributes, valid values are "true" or "false". A

    value of NULL means an attribute with a zero length string for its value
    i.e. cmd=NULL is actually transmitted as the string of 4 characters
    "cmd=".

    If a host is specified in a cmd-arg or addr, it is recommended that it
    be specified as a numeric address so as to avoid any ambiguities.

    In the case of rcmd authorizations, the authen_method will be set to
    TAC_PLUS_AUTHEN_METH_RCMD and the remote_user and remote_host attributes
    will provide the remote user and host information to enable rhost style
    authorization. The response may request that a privilege level be set
    for the user.

    The protocol attribute is intended for use with PPP. When service equals
    "ppp" and protocol equals "lcp", the message describes the PPP link
    layer service. For other values of protocol, this describes a PPP NCP
    (network layer service). A single PPP session can support multiple NCPs.

    The attributes addr, inacl, outacl, route and routing may be used for
    all network protocol types that are supported. Their format and meaning
    is determined by the values of the service or protocol attributes. Not
    all are necessarily implemented for any given network protocol.

       12.1.  The authorization RESPONSE packet body



             1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8

          +----------------+----------------+----------------+----------------+
          |    status      |     arg_cnt    |         server_msg len          |
          +----------------+----------------+----------------+----------------+
          +            data len             |    arg 1 len   |    arg 2 len   |
          +----------------+----------------+----------------+----------------+
          |      ...       |   arg N len    |         server_msg ...
          +----------------+----------------+----------------+----------------+
          |   data ...
          +----------------+----------------+----------------+----------------+
          |   arg 1 ...
          +----------------+----------------+----------------+----------------+
          |   arg 2 ...
          +----------------+----------------+----------------+----------------+
          |   ...
          +----------------+----------------+----------------+----------------+
          |   arg N ...
          +----------------+----------------+----------------+----------------+



    status
       This field indicates the authorization status

       TAC_PLUS_AUTHOR_STATUS_PASS_ADD  := 0x01

       TAC_PLUS_AUTHOR_STATUS_PASS_REPL := 0x02

       TAC_PLUS_AUTHOR_STATUS_FAIL      := 0x10

       TAC_PLUS_AUTHOR_STATUS_ERROR     := 0x11

       TAC_PLUS_AUTHOR_STATUS_FOLLOW    := 0x21


    server_msg

       This is an ASCII string that may be presented to the user. The decision
       to present this message is client specific.

    data

       This is an ASCII string that may be presented on an administrative
       display, console or log. The decision to present this message is client
       specific.

    arg_cnt

       The number of authorization arguments to follow.

    arg

       An attribute-value pair that describes the command to be performed. (see
       below)

       If the status equals TAC_PLUS_AUTHOR_STATUS_FAIL, then the appropriate
       action is to deny the user action.

       If the status equals TAC_PLUS_AUTHOR_STATUS_PASS_ADD, then the
       arguments specified in the request are authorized and the arguments in
       the response are to be used IN ADDITION to those arguments.

       If the status equals TAC_PLUS_AUTHOR_STATUS_PASS_REPL then the
       arguments in the request are to be completely replaced by the
       arguments in the response.

       If the intended action is to approve the authorization with no
       modifications, then the status should be set to
       TAC_PLUS_AUTHOR_STATUS_PASS_ADD and the arg_cnt should be set to
       0.

       A status of TAC_PLUS_AUTHOR_STATUS_ERROR indicates an error occurred
       on the daemon.

       When the status equals TAC_PLUS_AUTHOR_STATUS_FOLLOW, then the arg_cnt
       MUST be 0. In that case, the actions to be taken and the contents of
       the data field are identical to the TAC_PLUS_AUTHEN_STATUS_FOLLOW
       status for Authentication.

       None of the arg values have any relevance if an ERROR is set."""

    def __init__(self, session_id: Optional[int] = None, secret: Optional[bytes] = None) -> None:
        "Initialise this authz packet"
        super().__init__(session_id, secret)
        self._type = TAC_PLUS_AUTHOR
        self._fields: Dict[str, Any] = {}
        self.authen_method: AuthenMethod = AuthenMethod.NOT_SET
        self.priv_lvl: int = 0
        self.authen_type: int = 0
        self.authen_service: int = 0
        self.user: str = ""
        self.port: str = ""
        self.rem_addr: str = ""
        self.status: AuthStatus = AuthStatus.FAIL  # Default to FAIL
        self.args: List[tuple[str, str, bool]] = []  # List of (attr, value, mandatory) tuples

    def set_status(self, status: AuthStatus) -> None:
        """Set the authorization status.

        Args:
            status: Authorization status to set

        Raises:
            ValueError: If status is not a valid AuthStatus value
        """
        if not isinstance(status, AuthStatus):
            raise ValueError("Status must be a valid AuthStatus enum value")
        self.status = status

    def pack(self) -> bytes:
        """Pack the authorization request into bytes format.

        Returns:
            bytes: The packed authorization request
        """
        # Calculate lengths
        user_len: int = len(self.user)
        port_len: int = len(self.port)
        rem_addr_len: int = len(self.rem_addr)
        arg_cnt: int = len(self.args)

        # Create the header portion
        header = bytearray(
            [
                self.authen_method,
                self.priv_lvl,
                self.authen_type,
                self.authen_service,
                user_len,
                port_len,
                rem_addr_len,
                arg_cnt,
            ]
        )

        # Add argument lengths
        for attr, value, _ in self.args:
            arg_str: str = f"{attr}={'=' if _ else '*'}{value}"
            header.append(len(arg_str))

        # Add the variable length fields
        body = bytearray()
        body.extend(self.user.encode())
        body.extend(self.port.encode())
        body.extend(self.rem_addr.encode())

        # Add the arguments
        for attr, value, mandatory in self.args:
            separator = "=" if mandatory else "*"
            arg_str = f"{attr}{separator}{value}"
            body.extend(arg_str.encode())

        return bytes(header + body)

    @classmethod
    def unpack(cls, data: bytes) -> "Authorization":
        """Unpack bytes into an Authorization object.

        Args:
            data: Raw bytes to unpack

        Returns:
            Authorization: New Authorization instance
        """
        auth = cls()

        # Unpack the fixed header
        auth.authen_method = AuthenMethod(data[0])
        auth.priv_lvl = data[1]
        auth.authen_type = data[2]
        auth.authen_service = data[3]

        user_len: int = data[4]
        port_len: int = data[5]
        rem_addr_len: int = data[6]
        arg_cnt: int = data[7]

        # Get argument lengths
        arg_lengths = []
        offset = 8
        for _ in range(arg_cnt):
            arg_lengths.append(data[offset])
            offset += 1

        # Extract user, port, and rem_addr
        auth.user = data[offset : offset + user_len].decode()
        offset += user_len

        auth.port = data[offset : offset + port_len].decode()
        offset += port_len

        auth.rem_addr = data[offset : offset + rem_addr_len].decode()
        offset += rem_addr_len

        # Extract arguments
        for arg_len in arg_lengths:
            arg_data: str = data[offset : offset + arg_len].decode()
            if "=" in arg_data:
                attr, value = arg_data.split("=", 1)
                auth.args.append((attr, value, True))
            elif "*" in arg_data:
                attr, value = arg_data.split("*", 1)
                auth.args.append((attr, value, False))
            offset += arg_len

        return auth

    def add_arg(self, attr: str, value: str, mandatory: bool = True) -> None:
        """Add an authorization argument.

        Args:
            attr: Attribute name
            value: Attribute value
            mandatory: Whether the argument is mandatory (True) or optional (False)
        """
        if len(f"{attr}={'=' if mandatory else '*'}{value}") > 255:
            raise ValueError("Argument length cannot exceed 255 characters")
        self.args.append((attr, value, mandatory))

    def validate(self) -> bool:
        """Validate the authorization packet.

        Returns:
            bool: True if valid, False otherwise
        """
        # Check mandatory service attribute
        service_arg = next((arg for arg in self.args if arg[0] == "service"), None)
        if not service_arg:
            return False

        # Validate cmd attribute for shell service
        if service_arg[1] == "shell":
            cmd_arg = next((arg for arg in self.args if arg[0] == "cmd"), None)
            if not cmd_arg:
                return False

        # Validate remote_user and remote_host for RCMD authentication
        if self.authen_method == AuthenMethod.RCMD:
            remote_user = next((arg for arg in self.args if arg[0] == "remote_user"), None)
            remote_host = next((arg for arg in self.args if arg[0] == "remote_host"), None)
            if not (remote_user and remote_host):
                return False

        return True


# }}}


# {{{ class Accounting
class Accounting(Packet):
    """
       13.  Accounting

       TACACS+ accounting is very similar to authorization. The packet for-
       mat is also similar. There is a fixed portion and an extensible por-
       tion. The extensible portion uses all the same attribute-value pairs
       that authorization uses, and adds several more.

       13.1.  The account REQUEST packet body


             1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8

          +----------------+----------------+----------------+----------------+
          |      flags     |  authen_method |    priv_lvl    |  authen_type   |
          +----------------+----------------+----------------+----------------+
          | authen_service |    user len    |    port len    |  rem_addr len  |
          +----------------+----------------+----------------+----------------+
          |    arg_cnt     |   arg 1 len    |   arg 2 len    |      ...       |
          +----------------+----------------+----------------+----------------+
          |   arg N len    |    user ...
          +----------------+----------------+----------------+----------------+
          |   port ...
          +----------------+----------------+----------------+----------------+
          |   rem_addr ...
          +----------------+----------------+----------------+----------------+
          |   arg 1 ...
          +----------------+----------------+----------------+----------------+
          |   arg 2 ...
          +----------------+----------------+----------------+----------------+
          |   ...
          +----------------+----------------+----------------+----------------+
          |   arg N ...
          +----------------+----------------+----------------+----------------+


    flags

       This holds bitmapped flags.

       TAC_PLUS_ACCT_FLAG_MORE     := 0x01 (deprecated)

       TAC_PLUS_ACCT_FLAG_START    := 0x02

       TAC_PLUS_ACCT_FLAG_STOP     := 0x04

       TAC_PLUS_ACCT_FLAG_WATCHDOG := 0x08

       All other fields are defined in the authorization and authentication
       sections above and have the same semantics.

       The following new attributes are defined for TACACS+ accounting only.
       When these attribute-value pairs are included in the argument list,
       they should precede any attribute-value pairs that are defined in the
       authorization section above.

    Table 2: Accounting Attribute-value Pairs


    task_id

       Start and stop records for the same event MUST have matching (unique)
       task_id's

    start_time

       The time the action started (in seconds since the epoch, 12:00am Jan
       1 1970).

    stop_time

       The time the action stopped (in seconds since the epoch.)

    elapsed_time

       The elapsed time in seconds for the action. Useful when the device
       does not keep real time.

    timezone

       The timezone abbreviation for all timestamps included in this packet.

    event

       Used only when "service=system". Current values are "net_acct",
       "cmd_acct", "conn_acct", "shell_acct" "sys_acct" and "clock_change".
       These indicate system level changes. The flags field SHOULD indicate
       whether the service started or stopped.

    reason

       Accompanies an event attribute. It describes why the event occurred.

    bytes

       The number of bytes transferred by this action

    bytes_in

       The number of input bytes transferred by this action

    bytes_out

       The number of output bytes transferred by this action

    paks

       The number of packets transferred by this action.

    paks_in

       The number of input packets transferred by this action.

    paks_out

       The number of output packets transferred by this action.

    status

       The numeric status value associated with the action. This is a signed
       four (4) byte word in network byte order. 0 is defined as success.
       Negative numbers indicate errors. Positive numbers indicate non-error
       failures. The exact status values may be defined by the client.

    err_msg

       An ascii string describing the status of the action.

       NOTE: All numeric values in an attribute-value string are provided as
       decimal ASCII numbers.

       13.2.  The accounting REPLY packet body

       The response to an accounting message is used to  indicate  that  the
       accounting   function  on  the  daemon  has  completed  and  securely
       committed the record. This provides  the  client  the  best  possible
       guarantee that the data is indeed logged.



             1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8

          +----------------+----------------+----------------+----------------+
          |         server_msg len          |            data len             |
          +----------------+----------------+----------------+----------------+
          |     status     |         server_msg ...
          +----------------+----------------+----------------+----------------+
          |     data ...
          +----------------+



    status

       This is the return status. Values are:
       TAC_PLUS_ACCT_STATUS_SUCCESS    := 0x01

       TAC_PLUS_ACCT_STATUS_ERROR      := 0x02

       TAC_PLUS_ACCT_STATUS_FOLLOW     := 0x21

    server_msg

       This is an ASCII string that may be presented to the user. The deci-
       sion to present this message is client specific.

    data

       This is an ASCII string that may be presented on an administrative
       display, console or log. The decision to present this message is
       client specific.

       When the status equals TAC_PLUS_ACCT_STATUS_FOLLOW, then the actions
       to be taken and the contents of the data field are identical to the

       TAC_PLUS_AUTHEN_STATUS_FOLLOW status for Authentication.

       The daemon MUST terminate the session after sending a REPLY.

       The TAC_PLUS_ACCT_FLAG_START flag indicates that this is a start
       accounting message. Start messages should only be sent once when a
       task is started. The TAC_PLUS_ACCT_FLAG_STOP indicates that this is a
       stop record and that the task has terminated. The
       TAC_PLUS_ACCT_FLAG_WATCHDOG flag means that this is an update record.
       Update records are sent at the client's discretion when the task is
       still running.

       The START and STOP flags are mutually exclusive. When the WATCHDOG
       flag is set along with the START flag, it indicates that the update
       record is a duplicate of the original START record. If the START flag
       is not set, then this indicates a minimal record indicating only that
       task is still running. The STOP flag MUST NOT be set in conjunction
       with the WATCHDOG flag."""

    def __init__(self, session_id: Optional[int] = None, secret: Optional[bytes] = None) -> None:
        "Initialise this acct packet"
        super().__init__(session_id, secret)
        self._type = TAC_PLUS_ACCT
        self._fields: Dict[str, Any] = {}

        # Fixed header fields
        self.flags: int = 0
        self.authen_method: int = 0
        self.priv_lvl: int = 0
        self.authen_type: int = 0
        self.authen_service: int = 0

        # Variable length fields
        self.user: str = ""
        self.port: str = ""
        self.rem_addr: str = ""
        self.args: List[str] = []

        # Server response fields
        self.status: AccountingStatus = AccountingStatus.ERROR
        self.server_msg: str = ""
        self.data: str = ""

    def set_flag(self, flag: AccountingFlags) -> None:
        """Set an accounting flag.

        Args:
            flag: Flag to set

        Raises:
            ValueError: If START and STOP flags are set together or
                       if STOP and WATCHDOG flags are set together
        """
        if flag == AccountingFlags.START and self.flags & AccountingFlags.STOP:
            raise ValueError("START and STOP flags are mutually exclusive")

        if flag == AccountingFlags.WATCHDOG and self.flags & AccountingFlags.STOP:
            raise ValueError("WATCHDOG and STOP flags cannot be combined")

        self.flags |= flag

    def pack(self) -> bytes:
        """Pack the accounting packet into bytes.

        Returns:
            bytes: The packed accounting packet
        """
        # Calculate lengths
        user_len = len(self.user)
        port_len = len(self.port)
        rem_addr_len = len(self.rem_addr)
        arg_cnt = len(self.args)

        # Create header
        header = bytearray(
            [
                self.flags,
                self.authen_method,
                self.priv_lvl,
                self.authen_type,
                self.authen_service,
                user_len,
                port_len,
                rem_addr_len,
                arg_cnt,
            ]
        )

        # Add argument lengths
        for arg in self.args:
            header.append(len(arg))

        # Create body
        body = bytearray()
        body.extend(self.user.encode())
        body.extend(self.port.encode())
        body.extend(self.rem_addr.encode())

        # Add arguments
        for arg in self.args:
            body.extend(arg.encode())

        return bytes(header + body)

    def pack_response(self) -> bytes:
        """Pack the accounting response packet.

        Returns:
            bytes: The packed response packet
        """
        server_msg_len = len(self.server_msg)
        data_len = len(self.data)

        header = bytearray()
        # Add lengths as 16-bit integers
        header.extend(server_msg_len.to_bytes(2, byteorder="big"))
        header.extend(data_len.to_bytes(2, byteorder="big"))
        header.append(self.status)

        body = bytearray()
        body.extend(self.server_msg.encode())
        body.extend(self.data.encode())

        return bytes(header + body)

    @classmethod
    def unpack(cls, data: bytes) -> "Accounting":
        """Unpack bytes into an Accounting object.

        Args:
            data: Raw bytes to unpack

        Returns:
            Accounting: New Accounting instance
        """
        acct = cls()

        # Unpack fixed header
        acct.flags = data[0]
        acct.authen_method = data[1]
        acct.priv_lvl = data[2]
        acct.authen_type = data[3]
        acct.authen_service = data[4]

        user_len = data[5]
        port_len = data[6]
        rem_addr_len = data[7]
        arg_cnt = data[8]

        # Get argument lengths
        offset = 9
        arg_lengths = []
        for _ in range(arg_cnt):
            arg_lengths.append(data[offset])
            offset += 1

        # Extract variable length fields
        acct.user = data[offset : offset + user_len].decode()
        offset += user_len

        acct.port = data[offset : offset + port_len].decode()
        offset += port_len

        acct.rem_addr = data[offset : offset + rem_addr_len].decode()
        offset += rem_addr_len

        # Extract arguments
        for arg_len in arg_lengths:
            acct.args.append(data[offset : offset + arg_len].decode())
            offset += arg_len

        return acct

    @classmethod
    def unpack_response(cls, data: bytes) -> "Accounting":
        """Unpack response bytes into an Accounting object.

        Args:
            data: Raw response bytes to unpack

        Returns:
            Accounting: New Accounting instance with response fields
        """
        acct = cls()

        # Get lengths (16-bit integers)
        server_msg_len = int.from_bytes(data[0:2], byteorder="big")
        data_len = int.from_bytes(data[2:4], byteorder="big")

        # Get status
        acct.status = AccountingStatus(data[4])

        # Get variable length fields
        offset = 5
        acct.server_msg = data[offset : offset + server_msg_len].decode()
        offset += server_msg_len

        acct.data = data[offset : offset + data_len].decode()

        return acct

    def add_arg(self, attr: str, value: str) -> None:
        """Add an accounting argument.

        Args:
            attr: Attribute name
            value: Attribute value
        """
        self.args.append(f"{attr}={value}")

    def validate(self) -> bool:
        """Validate the accounting packet.

        Returns:
            bool: True if valid, False otherwise
        """
        # Check for mutually exclusive flags
        if (self.flags & AccountingFlags.START and self.flags & AccountingFlags.STOP) or (
            self.flags & AccountingFlags.WATCHDOG and self.flags & AccountingFlags.STOP
        ):
            return False

        # Validate task_id presence for START/STOP records
        if self.flags & (AccountingFlags.START | AccountingFlags.STOP):
            task_id = next((arg for arg in self.args if arg.startswith("task_id=")), None)
            if not task_id:
                return False

        return True


# {{{ Further details from the RFC
"""
   14.  Compatibility between Minor Versions 0 and 1

   Whenever a TACACS+ daemon receives a packet with a minor_version that
   it does not support, it should return an ERROR status with the
   minor_version set to the supported value closest to the requested
   value.

   The changes between minor_version 0 and 1 all deal with the way that
   CHAP, ARAP and PAP authentications are handled.

   In minor_version 0, CHAP, ARAP and outbound PAP authentications were
   performed by the NAS sending a SENDPASS packet to the daemon. The
   SENDPASS requested a copy of the user's plaintext password so that
   the NAS could complete the authentication. The CHAP hashing and ARAP
   encryption were all performed on the NAS. Inbound PAP performed a
   normal LOGIN, sending the username in the START packet and then wait-
   ing for a GETPASS and sending the password in a CONTINUE packet.

   In minor_version 1, CHAP, ARAP and inbound PAP use LOGIN to perform
   inbound authentication and the exchanges use the data field so that
   the NAS only sends a single START packet and expects to receive a
   PASS or FAIL. SENDPASS has been deprecated and SENDAUTH introduced,
   so that the NAS can request authentication credentials for authenti-
   cating to a remote peer. SENDAUTH is only used for PPP when perform-
   ing outbound authentication.

   NOTE: Only those requests which have changed from their minor_version
   0 implementation (i.e. ARAP, CHAP and PAP) should use the new
   minor_version number of 1. All other requests (whose implementation
   has not changed) MUST continue to use the same minor_version number
   of 0 that they have always used.

   If a daemon or NAS implementation desires to provide support for
   minor_number 0 TACACS+ hosts, it MUST pay attention to the
   minor_version in the TACACS+ header (as it should anyway) and be
   prepared to support the SENDPASS operation.

   The removal of SENDPASS was prompted by security concerns, and imple-
   mentors should think very carefully about how they wish to provide
   this service. On a NAS, the minor_version 0 compatibility can be lay-
   ered such that higher layers only need to understand the
   minor_version 1 methodology, with the compatibility layer translating
   requests appropriately when contacting an older daemon.

   On a TACACS+ server, when detecting minor_number 0, the daemon should
   allow for PAP authentications that do not send the password in the
   data field, but instead expect to read the PAP password from a subse-
   quent CONTINUE packet.

   If the daemon supports SENDPASS, then it should be prepared to handle
   such requests for CHAP and ARAP and even PAP, when outbound authenti-
   cation takes place.


   15.  Notes to Implementors

   For those interested in integrating one-time password support into
   TACACS+ daemons, there are some subtleties to consider.  TACACS+ is
   designed to make this straightforward, but two cases require some
   extra care.

   One-time password support with ARAP and PPP's CHAP authentication
   protocols is NOT straightforward, but there are work arounds. The
   problem lies in the nature of ARAP and CHAP authentication. Both
   employ a challenge-response protocol that requires a copy of the
   cleartext password to be stored at both ends. Unfortunately, due to
   their cryptographic nature, one-time password systems can rarely pro-
   vide the cleartext version of the next password.

   A simple workaround is to have the user enter their username as a
   combination of the username and the one-time password, separated by a
   special character, and a fixed password can be used in the password
   field. The fixed password can be assigned on a per user basis or as a
   single site-wide password.

   For the separator character, Cisco Systems has been using the `*'
   (asterisk) character. After some deliberation, it was decided that it
   was the least likely character to be found in a username.
"""
# }}}

if __name__ == "__main__":
    obj = Authentication(secret="fred".encode())
    obj._body = "Wibble=Wobble".encode()
    obj._seq_no = 3
    obj._session_id = 32769
    packet = obj.encode()
    print(repr(obj))
    newobj = Packet.decode(packet, "fred".encode())
    print(repr(newobj))
