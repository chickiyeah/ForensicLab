"""forensiclab.mongodb 단위 테스트 (stdlib unittest)."""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.mongodb import (  # noqa: E402
    MONGODB_PORTS,
    OP_CODE_NAMES,
    MongodbMessage,
    parse_mongodb_message,
)

# ---- 최소 BSON/와이어 빌더(테스트 전용) ---------------------------------

def _cstr(s: str) -> bytes:
    return s.encode("utf-8") + b"\x00"


def _bson_str(key: str, val: str) -> bytes:
    """BSON string 요소(type 0x02)."""
    vb = val.encode("utf-8") + b"\x00"
    return b"\x02" + _cstr(key) + struct.pack("<i", len(vb)) + vb


def _bson_i32(key: str, val: int) -> bytes:
    return b"\x10" + _cstr(key) + struct.pack("<i", val)


def _bson_doc(*elements: bytes) -> bytes:
    body = b"".join(elements)
    total = 4 + len(body) + 1  # length prefix + elements + null terminator
    return struct.pack("<i", total) + body + b"\x00"


def _header(op_code: int, payload: bytes, request_id=1, response_to=0) -> bytes:
    msg_len = 16 + len(payload)
    return struct.pack("<iiii", msg_len, request_id, response_to, op_code) + payload


def _op_query(fcn: str, query: bytes, flags=0, skip=0, ret=-1) -> bytes:
    payload = struct.pack("<i", flags) + _cstr(fcn) + struct.pack("<ii", skip, ret) + query
    return _header(2004, payload)


def _op_msg(body_doc: bytes, flag_bits=0) -> bytes:
    payload = struct.pack("<I", flag_bits) + b"\x00" + body_doc  # kind 0 section
    return _header(2013, payload)


# ---- 헤더 파싱 ----------------------------------------------------------

class HeaderTest(unittest.TestCase):
    def test_op_msg_header_fields(self):
        msg = _op_msg(_bson_doc(_bson_i32("ping", 1), _bson_str("$db", "admin")))
        m = parse_mongodb_message(msg)
        self.assertIsInstance(m, MongodbMessage)
        self.assertEqual(m.op_code, 2013)
        self.assertEqual(m.op_name, "OP_MSG")
        self.assertEqual(m.request_id, 1)
        self.assertEqual(m.response_to, 0)
        self.assertTrue(m.is_request)
        self.assertEqual(m.message_length, len(msg))

    def test_response_not_request(self):
        msg = _header(1, b"", request_id=5, response_to=1)  # OP_REPLY
        m = parse_mongodb_message(msg)
        self.assertEqual(m.op_name, "OP_REPLY")
        self.assertFalse(m.is_request)

    def test_unknown_opcode_rejected(self):
        bad = struct.pack("<iiii", 32, 1, 0, 9999) + b"\x00" * 16
        self.assertIsNone(parse_mongodb_message(bad))

    def test_too_short_for_header(self):
        self.assertIsNone(parse_mongodb_message(b"\x10\x00\x00"))

    def test_empty(self):
        self.assertIsNone(parse_mongodb_message(b""))

    def test_negative_offset(self):
        self.assertIsNone(parse_mongodb_message(b"x" * 32, offset=-1))

    def test_message_length_too_small(self):
        bad = struct.pack("<iiii", 8, 1, 0, 2013)
        self.assertIsNone(parse_mongodb_message(bad))

    def test_message_length_too_large(self):
        bad = struct.pack("<iiii", 1 << 30, 1, 0, 2013)
        self.assertIsNone(parse_mongodb_message(bad))


# ---- OP_QUERY -----------------------------------------------------------

class OpQueryTest(unittest.TestCase):
    def test_handshake_ismaster(self):
        msg = _op_query("admin.$cmd", _bson_doc(_bson_i32("isMaster", 1)))
        m = parse_mongodb_message(msg)
        self.assertEqual(m.command, "isMaster")
        self.assertEqual(m.database, "admin")
        self.assertEqual(m.collection, "$cmd")
        self.assertEqual(m.full_collection_name, "admin.$cmd")
        self.assertTrue(m.is_handshake)
        self.assertTrue(m.is_admin_db)
        self.assertFalse(m.is_write)

    def test_find_collection(self):
        msg = _op_query("shop.users", _bson_doc(_bson_i32("find", 1)))
        m = parse_mongodb_message(msg)
        self.assertEqual(m.database, "shop")
        self.assertEqual(m.collection, "users")
        self.assertFalse(m.is_admin_db)

    def test_flags_captured(self):
        msg = _op_query("db.col", _bson_doc(_bson_i32("find", 1)), flags=4)
        m = parse_mongodb_message(msg)
        self.assertEqual(m.flag_bits, 4)


# ---- OP_MSG -------------------------------------------------------------

class OpMsgTest(unittest.TestCase):
    def test_command_and_db(self):
        msg = _op_msg(_bson_doc(_bson_i32("find", 1), _bson_str("$db", "shop")))
        m = parse_mongodb_message(msg)
        self.assertEqual(m.command, "find")
        self.assertEqual(m.database, "shop")

    def test_write_command(self):
        msg = _op_msg(_bson_doc(_bson_i32("insert", 1), _bson_str("$db", "shop")))
        m = parse_mongodb_message(msg)
        self.assertTrue(m.is_write)

    def test_destructive_drop(self):
        msg = _op_msg(_bson_doc(_bson_str("drop", "users"), _bson_str("$db", "shop")))
        m = parse_mongodb_message(msg)
        self.assertEqual(m.command, "drop")
        self.assertTrue(m.is_write)

    def test_hello_handshake(self):
        msg = _op_msg(_bson_doc(_bson_i32("hello", 1), _bson_str("$db", "admin")))
        m = parse_mongodb_message(msg)
        self.assertTrue(m.is_handshake)

    def test_document_sequence_section_skipped(self):
        # kind-0 본문 + kind-1 문서 시퀀스가 뒤따르는 경우에도 명령을 잡는다.
        body = _bson_doc(_bson_i32("insert", 1), _bson_str("$db", "shop"))
        seq_id = _cstr("documents")
        seq = struct.pack("<i", 4 + len(seq_id)) + seq_id
        payload = struct.pack("<I", 0) + b"\x00" + body + b"\x01" + seq
        msg = _header(2013, payload)
        m = parse_mongodb_message(msg)
        self.assertEqual(m.command, "insert")
        self.assertEqual(m.database, "shop")


# ---- 인증 ---------------------------------------------------------------

class AuthTest(unittest.TestCase):
    def test_saslstart_scram(self):
        msg = _op_msg(_bson_doc(
            _bson_i32("saslStart", 1),
            _bson_str("mechanism", "SCRAM-SHA-256"),
            _bson_str("$db", "admin"),
        ))
        m = parse_mongodb_message(msg)
        self.assertTrue(m.is_auth)
        self.assertEqual(m.auth_mechanism, "SCRAM-SHA-256")
        self.assertFalse(m.is_plaintext_auth)

    def test_saslstart_plain_is_plaintext(self):
        msg = _op_msg(_bson_doc(
            _bson_i32("saslStart", 1),
            _bson_str("mechanism", "PLAIN"),
            _bson_str("$db", "$external"),
        ))
        m = parse_mongodb_message(msg)
        self.assertTrue(m.is_auth)
        self.assertTrue(m.is_plaintext_auth)


# ---- 견고성 -------------------------------------------------------------

class RobustnessTest(unittest.TestCase):
    def test_truncated_bson_no_crash(self):
        full = _op_msg(_bson_doc(_bson_i32("find", 1), _bson_str("$db", "shop")))
        # 헤더 길이는 유지하되 BSON 본문을 잘라낸다.
        truncated = full[:20]
        m = parse_mongodb_message(truncated)
        self.assertIsInstance(m, MongodbMessage)  # 예외 없이 부분 파싱

    def test_offset_parsing(self):
        msg = _op_msg(_bson_doc(_bson_i32("ping", 1), _bson_str("$db", "admin")))
        m = parse_mongodb_message(b"\xde\xad\xbe\xef" + msg, offset=4)
        self.assertEqual(m.command, "ping")

    def test_opcode_names_complete(self):
        self.assertEqual(OP_CODE_NAMES[2013], "OP_MSG")
        self.assertIn(2004, OP_CODE_NAMES)

    def test_ports(self):
        self.assertIn(27017, MONGODB_PORTS)


if __name__ == "__main__":
    unittest.main()
