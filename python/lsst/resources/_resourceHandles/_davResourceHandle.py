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

from __future__ import annotations

__all__ = ("DavReadResourceHandle",)

import io
import logging
from collections.abc import Callable, Iterable
from typing import TYPE_CHECKING, AnyStr

from ..davutils import DavFileMetadata
from ._baseResourceHandle import BaseResourceHandle, CloseStatus

if TYPE_CHECKING:
    from ..dav import DavResourcePath


class DavReadResourceHandle(BaseResourceHandle[bytes]):
    """WebDAV-based specialization of `.BaseResourceHandle`.

    Parameters
    ----------
    mode : `str`
        Handle modes as described in the python `io` module.
    log : `~logging.Logger`
        Logger to used when writing messages.
    uri : `lsst.resources.dav.DavResourcePath`
        URI of remote resource.
    newline : `str` or `None`, optional
        When doing multiline operations, break the stream on given character.
        Defaults to newline. If a file is opened in binary mode, this argument
        is not used, as binary files will only split lines on the binary
        newline representation.
    """

    def __init__(
        self,
        mode: str,
        log: logging.Logger,
        uri: DavResourcePath,
        stat: DavFileMetadata,
        *,
        newline: AnyStr | None = None,
    ) -> None:
        super().__init__(mode, log, uri, newline=newline)
        self._uri: DavResourcePath = uri
        self._stat: DavFileMetadata = stat
        self._current_position = 0
        self._cache: io.BytesIO | None = None
        self._buffer: io.BytesIO | None = None
        self._closed = CloseStatus.OPEN

    def close(self) -> None:
        self._closed = CloseStatus.CLOSED
        self._cache = None

    @property
    def closed(self) -> bool:
        return self._closed == CloseStatus.CLOSED

    def fileno(self) -> int:
        raise io.UnsupportedOperation("DavReadResourceHandle does not have a file number")

    def flush(self) -> None:
        modes = set(self._mode)
        if {"w", "x", "a", "+"} & modes:
            raise io.UnsupportedOperation("DavReadResourceHandles are read only")

    @property
    def isatty(self) -> bool | Callable[[], bool]:
        return False

    def readable(self) -> bool:
        return True

    def readline(self, size: int = -1) -> bytes:
        raise io.UnsupportedOperation("DavReadResourceHandles Do not support line by line reading")

    def readlines(self, size: int = -1) -> Iterable[bytes]:
        raise io.UnsupportedOperation("DavReadResourceHandles Do not support line by line reading")

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        match whence:
            case io.SEEK_SET:
                if offset < 0:
                    raise ValueError(f"negative seek value {offset}")
                self._current_position = offset
            case io.SEEK_CUR:
                self._current_position += offset
            case io.SEEK_END:
                self._current_position = self._stat.size + offset
            case _:
                raise ValueError(f"unexpected value {whence} for whence in seek()")

        if self._current_position < 0:
            self._current_position = 0

        return self._current_position

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self._current_position

    def truncate(self, size: int | None = None) -> int:
        raise io.UnsupportedOperation("DavReadResourceHandles Do not support truncation")

    def writable(self) -> bool:
        return False

    def write(self, b: bytes, /) -> int:
        raise io.UnsupportedOperation("DavReadResourceHandles are read only")

    def writelines(self, b: Iterable[bytes], /) -> None:
        raise io.UnsupportedOperation("DavReadResourceHandles are read only")

    @property
    def _eof(self) -> bool:
        return self._current_position >= self._stat.size

    def _download_to_cache(self) -> io.BytesIO:
        """Download the entire content of the remote resource to an internal
        memory buffer.
        """
        if self._cache is None:
            self._cache = io.BytesIO()
            self._cache.write(self._uri.read())

        return self._cache

    def read(self, size: int = -1) -> bytes:
        if self._eof or size == 0:
            return b""

        # If this file's size is small than the buffer size configured for
        # this URI's client, download the entire file in one request and cache
        # its content. This avoids multiple roundtrips to the server
        # for retrieving small chunks.
        if self._stat.size <= self._uri._client._config.buffer_size:
            self._download_to_cache()

        # If we are asked to read the whole file content, cache the entire
        # file content and return a copy-on-write memory view of our internal
        # cache.
        if self._current_position == 0 and size == -1:
            cache = self._download_to_cache()
            self._current_position = self._stat.size
            return cache.getvalue()

        # This is a partial read. If we have already cached the whole file
        # content use the cache to build the return value.
        if self._cache is not None:
            start = self._current_position
            end = self._current_position = self._stat.size if size < 0 else start + size
            return self._cache.getvalue()[start:end]

        # We need to make a partial read from the server. Reuse our internal
        # I/O buffer to reduce memory allocations.
        if self._buffer is None:
            self._buffer = io.BytesIO()

        start = self._current_position
        end = self._stat.size if size < 0 else min(start + size, self._stat.size)
        self._buffer.seek(0)
        self._buffer.write(self._uri.read_range(start=start, end=end - 1))
        count = self._buffer.tell()
        self._current_position += count
        return self._buffer.getvalue()[0:count]

    def readinto(self, output: bytearray) -> int:
        """Read up to `len(output)` bytes into `output` and return the number
        of bytes read.
        """
        if self._eof or len(output) == 0:
            return 0

        data = self.read(len(output))
        output[:] = data
        return len(data)
