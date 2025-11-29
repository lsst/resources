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

from ..davutils import DavClient, redact_url
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
    stat : `DavFileMetadata`
        Information about this resource.
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
        file_size: int,
        encoding: str | None = None,
        *,
        newline: AnyStr | None = None,
    ) -> None:
        super().__init__(mode, log, uri, newline=newline)
        self._uri: DavResourcePath = uri
        self._client: DavClient = self._uri._client
        self._filesize: int = file_size
        self._encoding: str | None = "locale" if encoding is None else encoding
        self._closed = CloseStatus.OPEN
        self._current_position = 0
        self._cache: DavReadAheadCache = DavReadAheadCache(
            client=self._client,
            frontend_url=self._uri._internal_url,
            filesize=self._filesize,
            blocksize=self._uri._client._config.block_size,
            log=log,
        )
        self._log.debug("initializing read handle for %s [%d]", self._uri, id(self))

    def close(self) -> None:
        if self._closed != CloseStatus.CLOSED:
            self._log.debug("closing read handle for %s [%d]", self._uri, id(self))
            self._cache.release_backend()
            self._closed = CloseStatus.CLOSED

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

    def readlines(self, hint: int = -1) -> Iterable[bytes]:
        raise io.UnsupportedOperation("DavReadResourceHandles Do not support line by line reading")

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        self._log.debug(
            "handle seek for %s: offset=%d, whence=%d, current_position=%d",
            self._uri,
            offset,
            whence,
            self._current_position,
        )

        match whence:
            case io.SEEK_SET:
                if offset < 0:
                    raise ValueError(f"negative seek value {offset}")
                self._current_position = offset
            case io.SEEK_CUR:
                self._current_position += offset
            case io.SEEK_END:
                self._current_position = self._filesize + offset
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
        return self._current_position >= self._filesize

    def read(self, size: int = -1) -> bytes:
        self._log.debug(
            "handle read for %s: filesize=%d, current_position=%d, size=%d",
            self._uri,
            self._filesize,
            self._current_position,
            size,
        )

        if self.closed:
            raise ValueError("I/O operation on closed file")

        if size == 0 or self._eof:
            return b""

        if size < 0:
            # Read up to the end of the file
            size = self._filesize - self._current_position

        output = self._cache.fetch(start=self._current_position, end=self._current_position + size)
        self._current_position += len(output)

        self._log.debug("returning %d bytes from handle read for %s", len(output), self._uri)

        return output

    def readinto(self, output: bytearray) -> int:
        """Read up to `len(output)` bytes into `output` and return the number
        of bytes read.

        Parameters
        ----------
        output : `bytearray`
            Byte array to write output into.
        """
        if self._eof or len(output) == 0:
            return 0

        data = self.read(len(output))
        output[:] = data
        return len(data)


class DavReadAheadCache:
    """Helper read-ahead cache for fetching chunks of a DavResourceHandle.

    Parameters
    ----------
    client : `lsst.resources.davutils.DavClient`
        webDAV client to interact with the server to download data.
    backend_url : `str`
        URL of the resource to download data from.
    filesize : `int`
        Size in bytes of the remote file.
    blocksize : `int`
        Size in bytes of the block for this resource. This is the size we use
        to retrieve data from this resource.
    log : `logging.Logger`
        Logger object to emit log records.

    Notes
    -----
    Behavior of this cache is inspired from fsspec's ReadAheadCache class.
    https://github.com/fsspec/filesystem_spec/blob/master/fsspec/caching.py
    """

    def __init__(
        self, client: DavClient, frontend_url: str, filesize: int, blocksize: int, log: logging.Logger
    ) -> None:
        self._client: DavClient = client
        self._frontend_url: str = frontend_url
        self._filesize: int = filesize
        self._blocksize: int = blocksize
        self._cache = b""
        self._start: int = 0
        self._end: int = 0
        self._backend_url: str | None = None
        self._backend_released: bool = False
        self._log: logging.Logger = log

    def geturl(self) -> str:
        return redact_url(self._frontend_url)

    def fetch(self, start: int, end: int) -> bytes:
        """Fetch a chunk of the file and store it in memory.

        Parameters
        ----------
        start : `int`
            Position of the first byte of the chunk.
        end : `int`
            Position of the last byte of the chunk.

        Returns
        -------
        output: `bytes`
            A chunk of up to end-start bytes. The returned chunk is
            served directly from the in-memory buffer without fetching new
            data from the remote file if it is already cached. Otherwise,
            a new chunk is retrieved from the origin file server and cached
            in memory. The size of the chunk can be the configured block
            size for this particular kind of resource path or the remaining
            bytes in the file.
        """
        self._log.debug(
            "DavReadAheadCache.fetch: %s start=%d end=%d [total: %d]",
            self.geturl(),
            start,
            end,
            end - start,
        )
        start = max(0, start)
        end = min(end, self._filesize)
        if start >= self._filesize or start >= end:
            return b""

        if start >= self._start and end <= self._end:
            # The requested chunk is entirely cached
            return self._cache[start - self._start : end - self._start]

        # The requested chunk is not fully in cache. Repopulate the cache
        # with a number of blocks large enough to satisfy the requested chunk.
        blocks_to_fetch = 1 + ((end - start) // self._blocksize)
        bytes_to_fetch = self._blocksize * blocks_to_fetch
        end_range = min(self._filesize, start + bytes_to_fetch)
        start_range = max(0, end_range - bytes_to_fetch)

        self._log.debug(
            "populating handle cache for %s with %d blocks [%d - %d, total bytes: %d]",
            self.geturl(),
            blocks_to_fetch,
            start_range,
            end_range,
            end_range - start_range,
        )

        # Make a partial read and save the URL of this resource as obtained
        # from the backend server. Further requests don't need to go through
        # the front-end server again.
        #
        # NOTE: when reading parquet files with method pq.read_table(), the
        # resource handle is not automatically closed, so we cannot keep the
        # connection with the backend server open. So, for each partial read
        # request, we need to go through the frontend server to get redirected
        # again to the backend server with a new transaction identifier.
        _, self._cache = self._client.read_range(
            self._frontend_url, start=start_range, end=end_range - 1, release_backend=True
        )
        self._start = start_range
        self._end = self._start + len(self._cache)
        return self._cache[start - self._start : end - self._start]

    def release_backend(self) -> None:
        """Notify the backend server that we want it to release
        the resources it has allocated to serve partial read requests for
        this handle.
        """
        if self._backend_released:
            return

        self._backend_released = True
        if self._backend_url is not None:
            self._log.debug("releasing connection to backend for %s", self.geturl())
            self._client.release_backend(self._backend_url)
            self._backend_url = None
