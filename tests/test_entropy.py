"""forensiclab.entropy 단위 테스트 (stdlib unittest)."""

import math
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.entropy import (  # noqa: E402
    DEFAULT_WINDOW_SIZE,
    MAX_ENTROPY,
    EntropyWindow,
    byte_histogram,
    classify_entropy,
    shannon_entropy,
    sliding_entropy,
)


class ByteHistogramTest(unittest.TestCase):
    def test_length_always_256(self):
        self.assertEqual(len(byte_histogram(b"")), 256)
        self.assertEqual(len(byte_histogram(b"abc")), 256)

    def test_counts_correct(self):
        hist = byte_histogram(b"AAB")
        self.assertEqual(hist[0x41], 2)  # 'A'
        self.assertEqual(hist[0x42], 1)  # 'B'
        self.assertEqual(hist[0x43], 0)  # 'C' 미등장

    def test_sum_equals_length(self):
        data = bytes(range(256)) * 3
        self.assertEqual(sum(byte_histogram(data)), len(data))


class ShannonEntropyTest(unittest.TestCase):
    def test_empty_is_zero(self):
        self.assertEqual(shannon_entropy(b""), 0.0)

    def test_single_repeated_byte_is_zero(self):
        self.assertEqual(shannon_entropy(b"\x00" * 100), 0.0)
        self.assertEqual(shannon_entropy(b"AAAAAAAA"), 0.0)

    def test_uniform_all_bytes_is_max(self):
        # 256개 바이트 값이 한 번씩 → 완전 균일 → 정확히 8.0.
        data = bytes(range(256))
        self.assertAlmostEqual(shannon_entropy(data), 8.0, places=9)

    def test_two_equal_symbols_is_one_bit(self):
        # 두 값이 50:50 → 1 bit/byte.
        self.assertAlmostEqual(shannon_entropy(b"AB" * 50), 1.0, places=9)

    def test_known_distribution(self):
        # 'A':2, 'B':1, 'C':1 → -[0.5log0.5 + 0.25log0.25 + 0.25log0.25] = 1.5.
        self.assertAlmostEqual(shannon_entropy(b"AABC"), 1.5, places=9)

    def test_within_bounds(self):
        for data in (b"x", b"hello world", bytes(range(128))):
            h = shannon_entropy(data)
            self.assertGreaterEqual(h, 0.0)
            self.assertLessEqual(h, MAX_ENTROPY)

    def test_does_not_mutate_input(self):
        data = bytearray(b"forensic")
        snapshot = bytes(data)
        shannon_entropy(bytes(data))
        self.assertEqual(bytes(data), snapshot)


class SlidingEntropyTest(unittest.TestCase):
    def test_empty_returns_empty(self):
        self.assertEqual(sliding_entropy(b""), [])

    def test_non_overlapping_blocks_cover_all(self):
        data = b"A" * 10
        out = sliding_entropy(data, window_size=4)
        self.assertEqual([w.offset for w in out], [0, 4, 8])
        # 마지막 윈도우는 잔여 2바이트만.
        self.assertEqual([w.size for w in out], [4, 4, 2])

    def test_overlapping_step(self):
        data = b"ABCDEF"
        out = sliding_entropy(data, window_size=4, step=2)
        self.assertEqual([w.offset for w in out], [0, 2, 4])

    def test_step_defaults_to_window_size(self):
        out = sliding_entropy(b"x" * 8, window_size=4)
        self.assertEqual([w.offset for w in out], [0, 4])

    def test_window_entropy_values(self):
        # 앞 절반은 단조(엔트로피 0), 뒤 절반은 두 심볼(엔트로피 1).
        data = b"AAAA" + b"ABAB"
        out = sliding_entropy(data, window_size=4)
        self.assertAlmostEqual(out[0].entropy, 0.0, places=9)
        self.assertAlmostEqual(out[1].entropy, 1.0, places=9)

    def test_returns_entropy_window_instances(self):
        out = sliding_entropy(b"abcd", window_size=2)
        self.assertTrue(all(isinstance(w, EntropyWindow) for w in out))

    def test_invalid_window_size_raises(self):
        with self.assertRaises(ValueError):
            sliding_entropy(b"abc", window_size=0)

    def test_invalid_step_raises(self):
        with self.assertRaises(ValueError):
            sliding_entropy(b"abc", window_size=2, step=0)

    def test_default_window_size_constant(self):
        self.assertEqual(DEFAULT_WINDOW_SIZE, 256)


class ClassifyEntropyTest(unittest.TestCase):
    def test_high_entropy_encrypted_label(self):
        self.assertEqual(classify_entropy(7.9), "암호화/압축 가능성 높음")
        self.assertEqual(classify_entropy(7.5), "암호화/압축 가능성 높음")

    def test_boundary_buckets(self):
        self.assertEqual(classify_entropy(6.0), "고엔트로피(압축 데이터·미디어 등)")
        self.assertEqual(classify_entropy(4.0), "보통(실행 코드·구조화 데이터 등)")
        self.assertEqual(classify_entropy(1.0), "저엔트로피(텍스트·반복 패턴 등)")
        self.assertEqual(classify_entropy(0.0), "매우 낮음(단조 데이터·패딩 등)")

    def test_max_value_accepted(self):
        self.assertEqual(classify_entropy(8.0), "암호화/압축 가능성 높음")

    def test_out_of_range_raises(self):
        with self.assertRaises(ValueError):
            classify_entropy(-0.1)
        with self.assertRaises(ValueError):
            classify_entropy(8.1)

    def test_integration_with_shannon(self):
        # 균일 데이터는 분류상 최고 버킷에 들어가야 한다.
        label = classify_entropy(shannon_entropy(bytes(range(256))))
        self.assertEqual(label, "암호화/압축 가능성 높음")


if __name__ == "__main__":
    unittest.main()
