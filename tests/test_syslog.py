"""forensiclab.syslog 단위 테스트 (stdlib unittest)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.syslog import (  # noqa: E402
    SYSLOG_FACILITIES,
    SYSLOG_SEVERITIES,
    Syslog,
    parse_syslog,
)


class PriTests(unittest.TestCase):
    def test_facility_severity_decode(self):
        # PRI 34 = facility 4(auth) * 8 + severity 2(crit).
        s = parse_syslog("<34>Oct 11 22:14:15 host su: failed")
        self.assertEqual(s.pri, 34)
        self.assertEqual(s.facility, 4)
        self.assertEqual(s.severity, 2)
        self.assertEqual(s.facility_name, "auth")
        self.assertEqual(s.severity_name, "crit")

    def test_pri_zero(self):
        # PRI 0 = kern.emerg.
        s = parse_syslog("<0>kernel panic")
        self.assertEqual(s.facility, 0)
        self.assertEqual(s.severity, 0)
        self.assertEqual(s.facility_name, "kern")
        self.assertEqual(s.severity_name, "emerg")

    def test_pri_max(self):
        # PRI 191 = facility 23(local7) * 8 + severity 7(debug).
        s = parse_syslog("<191>local7.debug stuff")
        self.assertEqual(s.facility, 23)
        self.assertEqual(s.severity, 7)

    def test_no_pri_returns_none(self):
        self.assertIsNone(parse_syslog("Oct 11 22:14:15 host sshd: hi"))

    def test_pri_out_of_range_returns_none(self):
        self.assertIsNone(parse_syslog("<999>nope"))

    def test_non_numeric_pri_returns_none(self):
        self.assertIsNone(parse_syslog("<abc>nope"))

    def test_unterminated_pri_returns_none(self):
        self.assertIsNone(parse_syslog("<34 no close"))


class ImportanceTests(unittest.TestCase):
    def test_err_is_important(self):
        self.assertTrue(parse_syslog("<11>err msg").is_important)  # sev 3.

    def test_warning_not_important(self):
        self.assertFalse(parse_syslog("<12>warn msg").is_important)  # sev 4.


class Rfc3164Tests(unittest.TestCase):
    def test_bsd_with_tag_and_pid(self):
        line = "<34>Oct 11 22:14:15 mymachine sshd[1234]: Failed password"
        s = parse_syslog(line)
        self.assertFalse(s.is_rfc5424)
        self.assertIsNone(s.version)
        self.assertEqual(s.timestamp, "Oct 11 22:14:15")
        self.assertEqual(s.hostname, "mymachine")
        self.assertEqual(s.app_name, "sshd")
        self.assertEqual(s.proc_id, "1234")
        self.assertEqual(s.message, "Failed password")

    def test_bsd_tag_without_pid(self):
        s = parse_syslog("<13>Jan  1 00:00:00 web nginx: started")
        self.assertEqual(s.app_name, "nginx")
        self.assertIsNone(s.proc_id)
        self.assertEqual(s.message, "started")

    def test_bsd_no_timestamp_falls_back_to_message(self):
        s = parse_syslog("<6>just a bare message")
        self.assertIsNone(s.timestamp)
        self.assertEqual(s.message, "just a bare message")


class Rfc5424Tests(unittest.TestCase):
    def test_full_message_with_nil_sd(self):
        line = ("<34>1 2003-10-11T22:14:15.003Z mymachine.example.com "
                "su 1234 ID47 - 'su root' failed")
        s = parse_syslog(line)
        self.assertTrue(s.is_rfc5424)
        self.assertEqual(s.version, 1)
        self.assertEqual(s.timestamp, "2003-10-11T22:14:15.003Z")
        self.assertEqual(s.hostname, "mymachine.example.com")
        self.assertEqual(s.app_name, "su")
        self.assertEqual(s.proc_id, "1234")
        self.assertEqual(s.msg_id, "ID47")
        self.assertIsNone(s.structured_data)
        self.assertEqual(s.message, "'su root' failed")

    def test_structured_data_extracted(self):
        line = ('<165>1 2003-10-11T22:14:15.003Z host evntslog - ID47 '
                '[exampleSDID@32473 iut="3" eventID="1011"] log body')
        s = parse_syslog(line)
        self.assertEqual(s.structured_data,
                         '[exampleSDID@32473 iut="3" eventID="1011"]')
        self.assertEqual(s.message, "log body")
        self.assertEqual(s.app_name, "evntslog")

    def test_nil_fields_become_none(self):
        s = parse_syslog("<34>1 - - - - - -")
        self.assertEqual(s.version, 1)
        self.assertIsNone(s.timestamp)
        self.assertIsNone(s.hostname)
        self.assertIsNone(s.app_name)
        self.assertIsNone(s.message)

    def test_escaped_bracket_in_sd(self):
        # SD 값 안의 이스케이프된 ``\]`` 는 종단이 아니다.
        line = r'<34>1 - h app - - [id k="a\]b"] tail'
        s = parse_syslog(line)
        self.assertEqual(s.structured_data, r'[id k="a\]b"]')
        self.assertEqual(s.message, "tail")


class InputTypeTests(unittest.TestCase):
    def test_bytes_input(self):
        s = parse_syslog(b"<34>Oct 11 22:14:15 host su: msg")
        self.assertEqual(s.pri, 34)
        self.assertEqual(s.hostname, "host")

    def test_latin1_fallback(self):
        # 유효하지 않은 UTF-8 이라도 latin-1 로 복구한다.
        s = parse_syslog(b"<6>Oct 11 22:14:15 host app: \xff\xfe")
        self.assertIsNotNone(s)
        self.assertEqual(s.facility, 0)

    def test_property_none_when_no_pri_fields(self):
        # facility/severity 가 없는 합성 객체의 이름 프로퍼티는 None.
        empty = Syslog()
        self.assertIsNone(empty.facility_name)
        self.assertIsNone(empty.severity_name)


class TableTests(unittest.TestCase):
    def test_facility_table_complete(self):
        self.assertEqual(len(SYSLOG_FACILITIES), 24)

    def test_severity_table_complete(self):
        self.assertEqual(len(SYSLOG_SEVERITIES), 8)


if __name__ == "__main__":
    unittest.main()
