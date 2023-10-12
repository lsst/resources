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

__all__ = ("HttpReadResourceHandle",)

import io
from collections.abc import Callable, Iterable
from logging import Logger
from typing import AnyStr

import requests
from lsst.utils.timer import time_this

from ._baseResourceHandle import BaseResourceHandle, CloseStatus


class HttpReadResourceHandle(BaseResourceHandle[bytes]):
    """HTTP-based specialization of `.BaseResourceHandle`."""

    def __init__(
        self,
        mode: str,
        log: Logger,
        *,
        session: requests.Session | None = None,
        url: str | None = None,
        timeout: tuple[float, float] | None = None,
        newline: AnyStr | None = None,
    ) -> None:
        super().__init__(mode, log, newline=newline)
        if url is None:
            raise ValueError("Url must be specified when constructing this object")
        self._url = url
        if session is None:
            raise ValueError("Session must be specified when constructing this object")
        self._session = session

        if timeout is None:
            raise ValueError("timeout must be specified when constructing this object")
        self._timeout = timeout

        self._completeBuffer: io.BytesIO | None = None

        self._closed = CloseStatus.OPEN
        self._current_position = 0
        self._eof = False

    def close(self) -> None:
        self._closed = CloseStatus.CLOSED
        self._completeBuffer = None
        self._eof = True

    @property
    def closed(self) -> bool:
        return self._closed == CloseStatus.CLOSED

    def fileno(self) -> int:
        raise io.UnsupportedOperation("HttpReadResourceHandle does not have a file number")

    def flush(self) -> None:
        modes = set(self._mode)
        if {"w", "x", "a", "+"} & modes:
            raise io.UnsupportedOperation("HttpReadResourceHandles are read only")

    @property
    def isatty(self) -> bool | Callable[[], bool]:
        return False

    def readable(self) -> bool:
        return True

    def readline(self, size: int = -1) -> bytes:
        raise io.UnsupportedOperation("HttpReadResourceHandles Do not support line by line reading")

    def readlines(self, size: int = -1) -> Iterable[bytes]:
        raise io.UnsupportedOperation("HttpReadResourceHandles Do not support line by line reading")

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        self._eof = False
        if whence == io.SEEK_CUR and (self._current_position + offset) >= 0:
            self._current_position += offset
        elif whence == io.SEEK_SET and offset >= 0:
            self._current_position = offset
        else:
            raise io.UnsupportedOperation("Seek value is incorrect, or whence mode is unsupported")

        # handle if the complete file has be read already
        if self._completeBuffer is not None:
            self._completeBuffer.seek(self._current_position, whence)
        return self._current_position

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self._current_position

    def truncate(self, size: int | None = None) -> int:
        raise io.UnsupportedOperation("HttpReadResourceHandles Do not support truncation")

    def writable(self) -> bool:
        return False

    def write(self, b: bytes, /) -> int:
        raise io.UnsupportedOperation("HttpReadResourceHandles are read only")

    def writelines(self, b: Iterable[bytes], /) -> None:
        raise io.UnsupportedOperation("HttpReadResourceHandles are read only")

    def read(self, size: int = -1) -> bytes:
        if self._eof:
            # At EOF so always return an empty byte string.
            return b""

        # branch for if the complete file has been read before
        if self._completeBuffer is not None:
            result = self._completeBuffer.read(size)
            self._current_position += len(result)
            return result

        if self._completeBuffer is None and size == -1 and self._current_position == 0:
            # The whole file has been requested, read it into a buffer and
            # return the result
            self._completeBuffer = io.BytesIO()
            with time_this(self._log, msg="Read from remote resource %s", args=(self._url,)):
                resp = self._session.get(self._url, stream=False, timeout=self._timeout)
            if (code := resp.status_code) not in (requests.codes.ok, requests.codes.partial):
                raise FileNotFoundError(f"Unable to read resource {self._url}; status code: {code}")
            self._completeBuffer.write(resp.content)
            self._current_position = self._completeBuffer.tell()

            return self._completeBuffer.getbuffer().tobytes()

        # A partial read is required, either because a size has been specified,
        # or a read has previously been done. Any time we specify a byte range
        # we must disable the gzip compression on the server since we want
        # to address ranges in the uncompressed file. If we send ranges that
        # are interpreted by the server as offsets into the compressed file
        # then that is at least confusing and also there is no guarantee that
        # the bytes can be uncompressed.

        end_pos = self._current_position + (size - 1) if size >= 0 else ""
        headers = {"Range": f"bytes={self._current_position}-{end_pos}", "Accept-Encoding": "identity"}

        with time_this(
            self._log, msg="Read from remote resource %s using headers %s", args=(self._url, headers)
        ):
            resp = self._session.get(self._url, stream=False, timeout=self._timeout, headers=headers)

        if resp.status_code == requests.codes.range_not_satisfiable:
            # Must have run off the end of the file. A standard file handle
            # will treat this as EOF so be consistent with that. Do not change
            # the current position.
            self._eof = True
            return b""

        if (code := resp.status_code) not in (requests.codes.ok, requests.codes.partial):
            raise FileNotFoundError(
                f"Unable to read resource {self._url}, or bytes are out of range; status code: {code}"
            )

        len_content = len(resp.content)

        # verify this is not actually the whole file and the server did not lie
        # about supporting ranges
        if len_content > size or code != requests.codes.partial:
            self._completeBuffer = io.BytesIO()
            self._completeBuffer.write(resp.content)
            self._completeBuffer.seek(0)
            return self.read(size=size)

        # The response header should tell us the total number of bytes
        # in the file and also the current position we have got to in the
        # server.
        if "Content-Range" in resp.headers:
            content_range = resp.headers["Content-Range"]
            units, range_string = content_range.split(" ")
            if units == "bytes":
                range, total = range_string.split("/")
                if "-" in range:
                    _, end = range.split("-")
                    end_pos = int(end)
                    if total != "*" and end_pos >= int(total) - 1:
                        self._eof = True
            else:
                self._log.warning("Requested byte range from server but instead got: %s", content_range)

        # Try to guess that we overran the end. This will not help if we
        # read exactly the number of bytes to get us to the end and so we
        # will need to do one more read and get a 416.
        if len_content < size:
            self._eof = True

        self._current_position += len_content
        return resp.content
