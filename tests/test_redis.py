"""forensiclab.redis 단위 테스트 (stdlib unittest)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.redis import (  # noqa: E402
    REDIS_PORTS,
    RedisCommand,
    parse_redis_command,
)


def _resp(*tokens):
    """토큰들을 RESP Bulk String 배열로 직렬화한다."""
    msg = bytearray()
    msg += b"*" + str(len(tokens)).encode() + b"\r\n"
    for t in tokens:
        b = t.encode() if isinstance(t, str) else t
        msg += b"$" + str(len(b)).encode() + b"\r\n" + b + b"\r\n"
    return bytes(msg)


class ParseRespTest(unittest.TestCase):
    def test_basic_command(self):
        r = parse_redis_command(_resp("GET", "session:1"))
        self.assertIsInstance(r, RedisCommand)
        self.assertEqual(r.verb, "GET")
        self.assertEqual(r.args, ["session:1"])
        self.assertFalse(r.inline)
        self.assertEqual(r.arg_count, 2)

    def test_verb_uppercased(self):
        r = parse_redis_command(_resp("ping"))
        self.assertEqual(r.verb, "PING")

    def test_auth_password_plaintext(self):
        r = parse_redis_command(_resp("AUTH", "hunter2"))
        self.assertTrue(r.is_auth)
        self.assertEqual(r.password, "hunter2")
        self.assertIsNone(r.username)

    def test_auth_acl_user_password(self):
        r = parse_redis_command(_resp("AUTH", "admin", "s3cret"))
        self.assertTrue(r.is_auth)
        self.assertEqual(r.username, "admin")
        self.assertEqual(r.password, "s3cret")

    def test_config_set_dir_file_write_vector(self):
        r = parse_redis_command(_resp("CONFIG", "SET", "dir", "/root/.ssh"))
        self.assertTrue(r.is_config_set)
        self.assertEqual(r.config_set_param, "dir")
        self.assertTrue(r.is_file_write_vector)

    def test_config_set_dbfilename_file_write_vector(self):
        r = parse_redis_command(_resp("CONFIG", "SET", "dbfilename", "authorized_keys"))
        self.assertTrue(r.is_file_write_vector)

    def test_config_set_benign_not_file_write(self):
        r = parse_redis_command(_resp("CONFIG", "SET", "maxmemory", "100mb"))
        self.assertTrue(r.is_config_set)
        self.assertFalse(r.is_file_write_vector)

    def test_replication_vector(self):
        for verb in ("SLAVEOF", "REPLICAOF"):
            r = parse_redis_command(_resp(verb, "10.0.0.9", "6379"))
            self.assertTrue(r.is_replication, verb)

    def test_module_load(self):
        r = parse_redis_command(_resp("MODULE", "LOAD", "/tmp/exp.so"))
        self.assertTrue(r.is_module_load)

    def test_module_list_not_load(self):
        r = parse_redis_command(_resp("MODULE", "LIST"))
        self.assertFalse(r.is_module_load)

    def test_destructive(self):
        for verb in ("FLUSHALL", "FLUSHDB"):
            r = parse_redis_command(_resp(verb))
            self.assertTrue(r.is_destructive, verb)

    def test_non_auth_password_none(self):
        r = parse_redis_command(_resp("GET", "k"))
        self.assertIsNone(r.password)
        self.assertFalse(r.is_config_set)
        self.assertIsNone(r.config_set_param)


class InlineTest(unittest.TestCase):
    def test_inline_command(self):
        r = parse_redis_command(b"PING\r\n")
        self.assertEqual(r.verb, "PING")
        self.assertTrue(r.inline)

    def test_inline_with_args(self):
        r = parse_redis_command(b"AUTH letmein\r\n")
        self.assertTrue(r.is_auth)
        self.assertEqual(r.password, "letmein")
        self.assertTrue(r.inline)

    def test_inline_no_trailing_crlf(self):
        r = parse_redis_command(b"INFO")
        self.assertEqual(r.verb, "INFO")


class RobustnessTest(unittest.TestCase):
    def test_empty_and_offset(self):
        self.assertIsNone(parse_redis_command(b""))
        self.assertIsNone(parse_redis_command(_resp("GET", "k"), offset=-1))
        self.assertIsNone(parse_redis_command(_resp("GET", "k"), offset=999))

    def test_garbage_verb_rejected(self):
        # 숫자/기호로 시작하는 토큰은 명령 동사로 인정하지 않음.
        self.assertIsNone(parse_redis_command(b"123\r\n"))
        self.assertIsNone(parse_redis_command(b"\x00\x01\x02\r\n"))

    def test_resp_bad_count_rejected(self):
        self.assertIsNone(parse_redis_command(b"*x\r\n$3\r\nGET\r\n"))
        self.assertIsNone(parse_redis_command(b"*0\r\n"))  # 빈 배열

    def test_resp_truncated_value_partial(self):
        full = _resp("AUTH", "supersecret")
        truncated = full[:-5]  # 비밀번호 값 일부 손실
        r = parse_redis_command(truncated)
        self.assertEqual(r.verb, "AUTH")
        self.assertTrue(r.password.startswith("super"))

    def test_resp_truncated_after_header(self):
        # *2 선언했지만 본문이 없음 → 요소 없음 → None.
        self.assertIsNone(parse_redis_command(b"*2\r\n"))

    def test_absurd_element_count_rejected(self):
        self.assertIsNone(parse_redis_command(b"*999999999\r\n$3\r\nGET\r\n"))

    def test_offset_parsing(self):
        padded = b"\xff\xff" + _resp("GET", "k")
        r = parse_redis_command(padded, offset=2)
        self.assertEqual(r.verb, "GET")

    def test_ports_constant(self):
        self.assertIn(6379, REDIS_PORTS)


if __name__ == "__main__":
    unittest.main()
