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

"""Download a single file as parallel byte ranges.

This module is shared by URI schemes that can fetch a resource in byte
ranges. It holds nothing specific to any HTTP library: each scheme supplies a
function that returns the bytes of one range, and this module splits the file,
runs the requests in parallel, and assembles the result.
"""

from __future__ import annotations

__all__ = ("FetchRange", "RangeNotHonoredError", "download_ranges", "split_ranges")

import concurrent.futures
import os
import threading
from collections.abc import Callable, Iterable, Sequence

FetchRange = Callable[[int, int], Iterable[bytes]]
"""Return the bytes of the inclusive range ``(first, last)``, in order."""


class _StoppedError(Exception):
    """Raised inside a worker that stopped because another range failed."""


class RangeNotHonoredError(Exception):
    """Raised by a range fetcher when the server returned the whole resource
    instead of the requested range.

    Callers catch this to fall back to a single-stream download.
    """


def split_ranges(size: int, n: int) -> list[tuple[int, int]]:
    """Split ``size`` bytes into ``n`` contiguous inclusive byte ranges.

    Parameters
    ----------
    size : `int`
        Total number of bytes. Must be positive.
    n : `int`
        Requested number of ranges. Reduced to ``size`` if larger.

    Returns
    -------
    ranges : `list` [ `tuple` [ `int`, `int` ] ]
        Inclusive ``(first, last)`` byte offsets. All ranges have the same
        length except the last, which also takes the remainder.
    """
    n = min(n, size)
    part = size // n
    ranges = [(i * part, (i + 1) * part - 1) for i in range(n)]
    ranges[-1] = (ranges[-1][0], size - 1)
    return ranges


def _pwrite_all(fd: int, data: bytes, offset: int) -> None:
    """Write all of ``data`` to ``fd`` at ``offset``.

    `os.pwrite` can write fewer bytes than requested (for example when the
    disk fills), and the file has already been extended to its full size, so
    any bytes not written would silently read back as zeros.
    """
    view = memoryview(data)
    while view:
        written = os.pwrite(fd, view, offset)
        if written <= 0:
            raise OSError(f"Unable to write to local file at offset {offset}")
        view = view[written:]
        offset += written


def _write_range(fd: int, first: int, last: int, fetch_range: FetchRange, stop: threading.Event) -> None:
    """Write one fetched range into ``fd`` at its offset and check its
    length, stopping early once ``stop`` is set.
    """
    offset = first
    chunks = iter(fetch_range(first, last))
    try:
        for chunk in chunks:
            if stop.is_set():
                raise _StoppedError()
            _pwrite_all(fd, chunk, offset)
            offset += len(chunk)
    finally:
        # Release the fetcher's resources (e.g. an open response) promptly.
        if (close := getattr(chunks, "close", None)) is not None:
            close()
    expected = last - first + 1
    received = offset - first
    if received != expected:
        raise ValueError(f"Byte range {first}-{last} returned {received} bytes, expected {expected}")


def download_ranges(path: str, size: int, ranges: Sequence[tuple[int, int]], fetch_range: FetchRange) -> None:
    """Download ``size`` bytes into ``path`` using parallel range requests.

    Parameters
    ----------
    path : `str`
        Local file to write. Created if needed and truncated to ``size``.
    size : `int`
        Total size of the resource in bytes. Must be positive.
    ranges : `~collections.abc.Sequence` [ `tuple` [ `int`, `int` ] ]
        Inclusive ``(first, last)`` byte ranges covering ``size`` bytes, each
        fetched by its own thread. `split_ranges` makes equal ones.
    fetch_range : `FetchRange`
        Function returning the bytes of an inclusive range. Called
        concurrently from several threads.

    Raises
    ------
    ValueError
        Raised if a range did not return exactly the requested number of
        bytes.
    RangeNotHonoredError
        Propagated from ``fetch_range`` so the caller can fall back to a
        single-stream download.

    Notes
    -----
    When a range fails, or the calling thread is interrupted, the other
    ranges stop at their next chunk. All threads have finished before this
    function returns or raises, so none is still writing to ``path``.
    """
    # Same permissions as open(path, "wb"); os.open defaults to 0o777.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o666)
    try:
        os.ftruncate(fd, size)
        first_error: BaseException | None = None
        stop = threading.Event()
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(ranges)) as executor:
            futures = [
                executor.submit(_write_range, fd, first, last, fetch_range, stop) for first, last in ranges
            ]
            try:
                for future in concurrent.futures.as_completed(futures):
                    error = future.exception()
                    if error is not None and not isinstance(error, _StoppedError) and first_error is None:
                        first_error = error
                        stop.set()
            except BaseException:
                # Interrupted while waiting; stop the workers before the
                # executor waits for them on exit.
                stop.set()
                raise
        if first_error is not None:
            raise first_error
    finally:
        os.close(fd)
