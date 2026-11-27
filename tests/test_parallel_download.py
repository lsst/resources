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
import unittest.mock
from collections.abc import Iterator

from lsst.resources._parallel_download import RangeNotHonoredError, download_ranges, split_ranges
from lsst.resources.utils import makeTestTempDir, removeTestTempDir

TESTDIR = os.path.abspath(os.path.dirname(__file__))

BODY = bytes(range(64))
RANGES = [(0, 15), (16, 31), (32, 47), (48, 63)]


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

        download_ranges(self.path, len(BODY), RANGES, fetch)

        with open(self.path, "rb") as fd:
            self.assertEqual(fd.read(), BODY)
        self.assertEqual(set(calls), {(0, 15), (16, 31), (32, 47), (48, 63)})

    def test_file_mode_matches_open(self) -> None:
        # The downloaded file must get the same permissions as a file
        # created with open(), not be executable.
        reference = os.path.join(self.tmpdir, "reference.dat")
        with open(reference, "wb"):
            pass
        download_ranges(self.path, len(BODY), RANGES, _chunks)
        self.assertEqual(os.stat(self.path).st_mode, os.stat(reference).st_mode)

    def test_short_write_is_completed(self) -> None:
        # os.pwrite may write fewer bytes than requested (e.g. as a disk
        # fills); the rest of the chunk must still be written.
        real_pwrite = os.pwrite

        def short_pwrite(fd: int, data: bytes, offset: int) -> int:
            return real_pwrite(fd, bytes(data[:1]), offset)

        with unittest.mock.patch("os.pwrite", side_effect=short_pwrite):
            download_ranges(self.path, len(BODY), RANGES, _chunks)
        with open(self.path, "rb") as fd:
            self.assertEqual(fd.read(), BODY)

    def test_failed_write_raises(self) -> None:
        # A write that makes no progress must not leave a zero-filled hole.
        with unittest.mock.patch("os.pwrite", return_value=0):
            with self.assertRaises(OSError):
                download_ranges(self.path, len(BODY), RANGES, _chunks)

    def test_uneven_ranges(self) -> None:
        # Ranges need not be equal: a small first range followed by the
        # rest split into larger ones.
        ranges = [(0, 3), (4, 23), (24, 43), (44, 63)]
        calls: list[tuple[int, int]] = []

        def fetch(first: int, last: int) -> Iterator[bytes]:
            calls.append((first, last))
            yield from _chunks(first, last)

        download_ranges(self.path, len(BODY), ranges, fetch)
        with open(self.path, "rb") as fd:
            self.assertEqual(fd.read(), BODY)
        self.assertEqual(sorted(calls), ranges)

    def test_short_range_raises(self) -> None:
        def fetch(first: int, last: int) -> Iterator[bytes]:
            if first == 16:
                last -= 1
            yield from _chunks(first, last)

        with self.assertRaises(ValueError):
            download_ranges(self.path, len(BODY), RANGES, fetch)

    def test_long_range_raises(self) -> None:
        def fetch(first: int, last: int) -> Iterator[bytes]:
            yield from _chunks(first, last)
            if first == 16:
                yield b"x"

        with self.assertRaises(ValueError):
            download_ranges(self.path, len(BODY), RANGES, fetch)

    def _slow_fetch(self, fail_first: int | None = None):
        """Return a fetcher that yields one byte at a time slowly, and
        counters recording how far each range got and how many are still
        running.
        """
        state = {"active": 0, "completed": 0}
        lock = threading.Lock()

        def fetch(first: int, last: int) -> Iterator[bytes]:
            if first == fail_first:
                raise OSError("connection reset")
            with lock:
                state["active"] += 1
            try:
                for start in range(first, last + 1):
                    time.sleep(0.02)
                    yield BODY[start : start + 1]
                with lock:
                    state["completed"] += 1
            finally:
                with lock:
                    state["active"] -= 1

        return fetch, state

    def test_error_stops_other_ranges(self) -> None:
        # A failed range stops the others early instead of letting them
        # download to the end, and no range is still running on return.
        fetch, state = self._slow_fetch(fail_first=16)
        with self.assertRaises(OSError):
            download_ranges(self.path, len(BODY), RANGES, fetch)
        self.assertEqual(state["active"], 0)
        self.assertEqual(state["completed"], 0)

    def test_interrupt_stops_ranges(self) -> None:
        # An interrupt in the calling thread (e.g. Ctrl-C) stops all ranges
        # promptly and propagates.
        fetch, state = self._slow_fetch()
        with unittest.mock.patch(
            "lsst.resources._parallel_download.concurrent.futures.as_completed",
            side_effect=KeyboardInterrupt,
        ):
            with self.assertRaises(KeyboardInterrupt):
                download_ranges(self.path, len(BODY), RANGES, fetch)
        self.assertEqual(state["active"], 0)
        self.assertEqual(state["completed"], 0)

    def test_range_not_honored_propagates(self) -> None:
        def fetch(first: int, last: int) -> Iterator[bytes]:
            if first == 0:
                raise RangeNotHonoredError("server ignored Range")
            yield from _chunks(first, last)

        with self.assertRaises(RangeNotHonoredError):
            download_ranges(self.path, len(BODY), RANGES, fetch)


if __name__ == "__main__":
    unittest.main()
