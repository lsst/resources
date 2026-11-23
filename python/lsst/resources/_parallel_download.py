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
from collections.abc import Callable, Iterable

FetchRange = Callable[[int, int], Iterable[bytes]]
"""Return the bytes of the inclusive range ``(first, last)``, in order."""


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


def _write_range(fd: int, first: int, last: int, fetch_range: FetchRange) -> None:
    """Write one fetched range into ``fd`` at its offset and check its
    length.
    """
    offset = first
    for chunk in fetch_range(first, last):
        os.pwrite(fd, chunk, offset)
        offset += len(chunk)
    expected = last - first + 1
    received = offset - first
    if received != expected:
        raise ValueError(f"Byte range {first}-{last} returned {received} bytes, expected {expected}")


def download_ranges(path: str, size: int, n_streams: int, fetch_range: FetchRange) -> None:
    """Download ``size`` bytes into ``path`` using parallel range requests.

    Parameters
    ----------
    path : `str`
        Local file to write. Created if needed and truncated to ``size``.
    size : `int`
        Total size of the resource in bytes. Must be positive.
    n_streams : `int`
        Number of ranges, each fetched by its own thread.
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
    If any range fails, the others are allowed to finish before the first
    exception is re-raised, so no thread is still writing to ``path`` when
    this function returns.
    """
    ranges = split_ranges(size, n_streams)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT)
    try:
        os.ftruncate(fd, size)
        first_error: BaseException | None = None
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(ranges)) as executor:
            futures = [executor.submit(_write_range, fd, first, last, fetch_range) for first, last in ranges]
            for future in concurrent.futures.as_completed(futures):
                if (error := future.exception()) is not None and first_error is None:
                    first_error = error
        if first_error is not None:
            raise first_error
    finally:
        os.close(fd)
