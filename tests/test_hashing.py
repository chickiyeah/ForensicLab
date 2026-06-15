"""forensiclab.hashing 단위 테스트 (stdlib unittest)."""

import hashlib
import io
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.hashing import (  # noqa: E402
    DEFAULT_ALGORITHMS,
    HashResult,
    compare_hash,
    hash_bytes,
    hash_file,
    hash_stream,
)

DATA = b"forensiclab hashing test vector"


class HashBytesTest(unittest.TestCase):
    def test_matches_hashlib_reference(self):
        result = hash_bytes(DATA)
        for algo in DEFAULT_ALGORITHMS:
            self.assertEqual(result[algo], hashlib.new(algo, DATA).hexdigest())

    def test_size_tracked(self):
        self.assertEqual(hash_bytes(DATA).size, len(DATA))

    def test_empty_input(self):
        result = hash_bytes(b"")
        self.assertEqual(result.size, 0)
        self.assertEqual(result["sha256"], hashlib.sha256(b"").hexdigest())

    def test_single_algorithm(self):
        result = hash_bytes(DATA, algorithms=["md5"])
        self.assertEqual(set(result.digests), {"md5"})

    def test_algorithm_name_case_insensitive(self):
        result = hash_bytes(DATA, algorithms=["SHA256"])
        self.assertEqual(result["sha256"], hashlib.sha256(DATA).hexdigest())

    def test_duplicate_algorithms_collapsed(self):
        result = hash_bytes(DATA, algorithms=["md5", "MD5", "md5"])
        self.assertEqual(set(result.digests), {"md5"})

    def test_unsupported_algorithm_raises(self):
        with self.assertRaises(ValueError):
            hash_bytes(DATA, algorithms=["not-a-real-algo"])

    def test_empty_algorithm_list_raises(self):
        with self.assertRaises(ValueError):
            hash_bytes(DATA, algorithms=[])


class HashStreamFileTest(unittest.TestCase):
    def test_stream_matches_bytes(self):
        stream = io.BytesIO(DATA)
        self.assertEqual(hash_stream(stream).digests, hash_bytes(DATA).digests)

    def test_chunked_large_input(self):
        big = b"A" * (1 << 18)  # 청크 경계를 여러 번 넘김
        self.assertEqual(
            hash_stream(io.BytesIO(big))["sha256"],
            hashlib.sha256(big).hexdigest(),
        )

    def test_hash_file_roundtrip(self):
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(DATA)
            path = tmp.name
        try:
            self.assertEqual(hash_file(path).digests, hash_bytes(DATA).digests)
        finally:
            os.unlink(path)

    def test_hash_file_missing_raises(self):
        with self.assertRaises(FileNotFoundError):
            hash_file(os.path.join(tempfile.gettempdir(), "no_such_forensic_file_xyz"))


class CompareHashTest(unittest.TestCase):
    def test_case_insensitive_match(self):
        self.assertTrue(compare_hash("ABCdef", "abcDEF"))

    def test_whitespace_stripped(self):
        self.assertTrue(compare_hash("  abc123  ", "abc123\n"))

    def test_mismatch(self):
        self.assertFalse(compare_hash("abc", "def"))

    def test_empty_never_matches(self):
        self.assertFalse(compare_hash("", ""))
        self.assertFalse(compare_hash("abc", ""))


class HashResultMatchesTest(unittest.TestCase):
    def setUp(self):
        self.result = hash_bytes(DATA)

    def test_matches_specific_algorithm(self):
        sha256 = hashlib.sha256(DATA).hexdigest().upper()
        self.assertTrue(self.result.matches(sha256, algorithm="sha256"))

    def test_matches_any_algorithm_when_unspecified(self):
        md5 = hashlib.md5(DATA).hexdigest()
        self.assertTrue(self.result.matches(md5))

    def test_no_match(self):
        self.assertFalse(self.result.matches("0" * 64))

    def test_returns_hashresult_type(self):
        self.assertIsInstance(self.result, HashResult)


if __name__ == "__main__":
    unittest.main()
