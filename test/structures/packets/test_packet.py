import struct
import unittest
from hashlib import md5
from unittest.mock import patch

from pytacs.structures.packets.packet import (
    TAC_PLUS_AUTHEN,
    TAC_PLUS_UNENCRYPTED_FLAG,
    Authentication,
    Packet,
)


class TestPacket(unittest.TestCase):

    def setUp(self):
        self.session_id = 12345
        self.secret = b"test_secret"
        self.packet = Packet(self.session_id, self.secret)

    def test_init(self):
        self.assertEqual(self.packet._session_id, self.session_id)
        self.assertEqual(self.packet._secret, self.secret)

    def test_repr(self):
        expected = "<Packet: Packet, Ver: 12/0>"
        self.assertEqual(repr(self.packet), expected)

    def test_str(self):
        expected = (
            "Packet:\tPacket\n"
            "Ver:\t12/0\n"
            "Type:\t0\n"
            "Seq:\t0\n"
            "Flags:\t0\n"
            "Ses'n:\t12345\n"
            "Length:\t0\n"
            "---------- BODY START\n"
            "\n"
            "---------- BODY END\n"
        )
        self.assertEqual(str(self.packet), expected)

    def test_encode_decode(self):
        self.packet._type = TAC_PLUS_AUTHEN
        self.packet._seq_no = 1
        self.packet._body = b"test_body"

        encoded = self.packet.encode()
        decoded = Packet.decode(encoded, self.secret)

        self.assertEqual(decoded._type, TAC_PLUS_AUTHEN)
        self.assertEqual(decoded._seq_no, 1)
        self.assertEqual(decoded._session_id, self.session_id)
        self.assertEqual(decoded._body, b"test_body")

    def test_reply(self):
        self.packet._type = TAC_PLUS_AUTHEN
        self.packet._seq_no = 1

        reply = self.packet.reply()

        self.assertEqual(reply._type, TAC_PLUS_AUTHEN)
        self.assertEqual(reply._seq_no, 2)
        self.assertEqual(reply._session_id, self.session_id)

    def test_flags(self):

        self.packet.reset_flag(TAC_PLUS_UNENCRYPTED_FLAG)
        self.assertFalse(self.packet.get_flag(TAC_PLUS_UNENCRYPTED_FLAG))

    @patch("pytacs.structures.packets.packet.md5")
    def test_crypt(self, mock_md5):
        mock_md5.return_value.digest.return_value = b"1234567890123456"

        self.packet._packet = b"0" * 12
        self.packet._body = b"test_body"

        encrypted = self.packet._Packet__crypt(self.packet._body)
        self.assertNotEqual(encrypted, self.packet._body)

        decrypted = self.packet._Packet__crypt(encrypted)
        self.assertEqual(decrypted, self.packet._body)


if __name__ == "__main__":
    unittest.main()
