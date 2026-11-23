# This file is part of lsst-resources.
#
# Developed for the LSST Data Management System.
# This product includes software developed by the LSST Project
# (https://www.lsst.org).
# See the COPYRIGHT file at the top-level directory of this distribution
# for details of code ownership.
#
# Use of this source code is governed by a 3-clause BSD-style
# license that can be found in the LICENSE file.

import os
import threading
import time
import unittest
from collections.abc import Iterator

from lsst.resources._parallel_download import RangeNotHonoredError, download_ranges, split_ranges
from lsst.resources.utils import makeTestTempDir, removeTestTempDir

TESTDIR = os.path.abspath(os.path.dirname(__file__))

BODY = bytes(range(64))


def _chunks(first: int, last: int, chunk_size: int = 3) -> Iterator[bytes]:
    """Yield ``BODY[first:last + 1]`` in small chunks."""
    for start in range(first, last + 1, chunk_size):
        yield BODY[start : min(start + chunk_size, last + 1)]


class ParallelDownloadTestCase(unittest.TestCase):
    """Tests for the scheme-neutral parallel range download driver."""

    def setUp(self) -> None:
        self.tmpdir = makeTestTempDir(TESTDIR)
        self.path = os.path.join(self.tmpdir, "out.dat")

    def tearDown(self) -> None:
        removeTestTempDir(self.tmpdir)

    def test_split_ranges(self) -> None:
        self.assertEqual(split_ranges(10, 3), [(0, 2), (3, 5), (6, 9)])
        self.assertEqual(split_ranges(16, 1), [(0, 15)])
        self.assertEqual(split_ranges(3, 8), [(0, 0), (1, 1), (2, 2)])

    def test_assembles_file(self) -> None:
        calls: list[tuple[int, int]] = []

        def fetch(first: int, last: int) -> Iterator[bytes]:
            calls.append((first, last))
            yield from _chunks(first, last)

        download_ranges(self.path, len(BODY), 4, fetch)

        with open(self.path, "rb") as fd:
            self.assertEqual(fd.read(), BODY)
        self.assertEqual(set(calls), {(0, 15), (16, 31), (32, 47), (48, 63)})

    def test_short_range_raises(self) -> None:
        def fetch(first: int, last: int) -> Iterator[bytes]:
            if first == 16:
                last -= 1
            yield from _chunks(first, last)

        with self.assertRaises(ValueError):
            download_ranges(self.path, len(BODY), 4, fetch)

    def test_long_range_raises(self) -> None:
        def fetch(first: int, last: int) -> Iterator[bytes]:
            yield from _chunks(first, last)
            if first == 16:
                yield b"x"

        with self.assertRaises(ValueError):
            download_ranges(self.path, len(BODY), 4, fetch)

    def test_error_propagates_after_others_finish(self) -> None:
        finished: list[tuple[int, int]] = []
        lock = threading.Lock()

        def fetch(first: int, last: int) -> Iterator[bytes]:
            if first == 16:
                raise OSError("connection reset")
            # Slow enough that the failing range is seen first.
            time.sleep(0.1)
            yield from _chunks(first, last)
            with lock:
                finished.append((first, last))

        with self.assertRaises(OSError):
            download_ranges(self.path, len(BODY), 4, fetch)
        self.assertEqual(set(finished), {(0, 15), (32, 47), (48, 63)})

    def test_range_not_honored_propagates(self) -> None:
        def fetch(first: int, last: int) -> Iterator[bytes]:
            if first == 0:
                raise RangeNotHonoredError("server ignored Range")
            yield from _chunks(first, last)

        with self.assertRaises(RangeNotHonoredError):
            download_ranges(self.path, len(BODY), 4, fetch)


if __name__ == "__main__":
    unittest.main()
