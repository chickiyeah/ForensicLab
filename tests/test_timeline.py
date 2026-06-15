"""forensiclab.timeline 단위 테스트 (stdlib unittest)."""

import os
import sys
import unittest
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.timeline import (  # noqa: E402
    Event,
    build_timeline,
    filter_range,
    group_by_source,
    time_span,
)


def _ev(y, mo, d, h=0, mi=0, s=0, source="log", desc=""):
    return Event(datetime(y, mo, d, h, mi, s), source, desc)


class EventTest(unittest.TestCase):
    def test_defaults(self):
        e = Event(datetime(2026, 1, 1), "exif")
        self.assertEqual(e.description, "")
        self.assertEqual(dict(e.data), {})

    def test_frozen(self):
        e = _ev(2026, 1, 1)
        with self.assertRaises(Exception):
            e.source = "x"  # type: ignore[misc]


class BuildTimelineTest(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(build_timeline([]), [])

    def test_sorts_ascending(self):
        a = _ev(2026, 1, 3)
        b = _ev(2026, 1, 1)
        c = _ev(2026, 1, 2)
        ordered = build_timeline([a, b, c])
        self.assertEqual([e.timestamp for e in ordered], [b.timestamp, c.timestamp, a.timestamp])

    def test_stable_for_equal_timestamps(self):
        # 같은 시각이면 입력 순서 유지(안정 정렬).
        first = _ev(2026, 1, 1, source="first")
        second = _ev(2026, 1, 1, source="second")
        ordered = build_timeline([first, second])
        self.assertEqual([e.source for e in ordered], ["first", "second"])

    def test_does_not_mutate_input(self):
        original = [_ev(2026, 1, 2), _ev(2026, 1, 1)]
        snapshot = list(original)
        build_timeline(original)
        self.assertEqual(original, snapshot)


class FilterRangeTest(unittest.TestCase):
    def setUp(self):
        self.events = [_ev(2026, 1, d) for d in (1, 2, 3, 4, 5)]

    def test_no_bounds_returns_all(self):
        self.assertEqual(len(filter_range(self.events)), 5)

    def test_inclusive_bounds(self):
        got = filter_range(self.events, datetime(2026, 1, 2), datetime(2026, 1, 4))
        self.assertEqual([e.timestamp.day for e in got], [2, 3, 4])

    def test_open_start(self):
        got = filter_range(self.events, end=datetime(2026, 1, 2))
        self.assertEqual([e.timestamp.day for e in got], [1, 2])

    def test_open_end(self):
        got = filter_range(self.events, start=datetime(2026, 1, 4))
        self.assertEqual([e.timestamp.day for e in got], [4, 5])

    def test_preserves_input_order(self):
        shuffled = [_ev(2026, 1, 3), _ev(2026, 1, 1), _ev(2026, 1, 2)]
        got = filter_range(shuffled)
        self.assertEqual([e.timestamp.day for e in got], [3, 1, 2])

    def test_start_after_end_raises(self):
        with self.assertRaises(ValueError):
            filter_range(self.events, datetime(2026, 1, 5), datetime(2026, 1, 1))

    def test_empty_when_nothing_in_range(self):
        got = filter_range(self.events, start=datetime(2026, 2, 1))
        self.assertEqual(got, [])


class GroupBySourceTest(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(group_by_source([]), {})

    def test_groups_and_keeps_order(self):
        events = [
            _ev(2026, 1, 1, source="apache"),
            _ev(2026, 1, 2, source="exif"),
            _ev(2026, 1, 3, source="apache"),
        ]
        grouped = group_by_source(events)
        self.assertEqual(list(grouped.keys()), ["apache", "exif"])  # 삽입 순서
        self.assertEqual([e.timestamp.day for e in grouped["apache"]], [1, 3])
        self.assertEqual([e.timestamp.day for e in grouped["exif"]], [2])


class TimeSpanTest(unittest.TestCase):
    def test_empty_is_none(self):
        self.assertIsNone(time_span([]))

    def test_single_event(self):
        e = _ev(2026, 1, 1, 12)
        self.assertEqual(time_span([e]), (e.timestamp, e.timestamp))

    def test_min_max(self):
        events = [_ev(2026, 1, 3), _ev(2026, 1, 1), _ev(2026, 1, 5), _ev(2026, 1, 2)]
        earliest, latest = time_span(events)
        self.assertEqual(earliest, datetime(2026, 1, 1))
        self.assertEqual(latest, datetime(2026, 1, 5))


if __name__ == "__main__":
    unittest.main()
