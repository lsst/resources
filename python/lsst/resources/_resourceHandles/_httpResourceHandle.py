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
from logging import Logger
from typing import AnyStr, Callable, Iterable, Optional, Union

import requests
from lsst.utils.timer import time_this

from ._baseResourceHandle import BaseResourceHandle, CloseStatus


class HttpReadResourceHandle(BaseResourceHandle[bytes]):
    def __init__(
        self,
        mode: str,
        log: Logger,
        *,
        session: Optional[requests.Session] = None,
        url: Optional[str] = None,
        timeout: Optional[tuple[float, float]] = None,
        newline: Optional[AnyStr] = None,
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

        self._completeBuffer: Optional[io.BytesIO] = None

        self._closed = CloseStatus.OPEN
        self._current_position = 0

    def close(self) -> None:
        self._closed = CloseStatus.CLOSED
        self._completeBuffer = None

    @property
    def closed(self) -> bool:
        return self._closed == CloseStatus.CLOSED

    def fileno(self) -> int:
        raise io.UnsupportedOperation("HttpReadResourceHandle does not have a file number")

    def flush(self) -> None:
        raise io.UnsupportedOperation("HttpReadResourceHandles are read only")

    @property
    def isatty(self) -> Union[bool, Callable[[], bool]]:
        return False

    def readable(self) -> bool:
        return True

    def readline(self, size: int = -1) -> AnyStr:
        raise io.UnsupportedOperation("HttpReadResourceHandles Do not support line by line reading")

    def readlines(self, size: int = -1) -> Iterable[bytes]:
        raise io.UnsupportedOperation("HttpReadResourceHandles Do not support line by line reading")

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
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

    def truncate(self, size: Optional[int] = None) -> int:
        raise io.UnsupportedOperation("HttpReadResourceHandles Do not support truncation")

    def writable(self) -> bool:
        return False

    def write(self, b: bytes, /) -> int:
        raise io.UnsupportedOperation("HttpReadResourceHandles are read only")

    def writelines(self, b: Iterable[bytes], /) -> None:
        raise io.UnsupportedOperation("HttpReadResourceHandles are read only")

    def read(self, size: int = -1) -> bytes:
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
            if (code := resp.status_code) not in (200, 206):
                raise FileNotFoundError(f"Unable to read resource {self._url}; status code: {code}")
            self._completeBuffer.write(resp.content)
            self._current_position = self._completeBuffer.tell()

            return self._completeBuffer.getbuffer().tobytes()

        # a partial read is required, either because a size has been specified,
        # or a read has previously been done.

        end_pos = self._current_position + (size - 1) if size >= 0 else ""
        headers = {"Range": f"bytes={self._current_position}-{end_pos}"}

        with time_this(self._log, msg="Read from remote resource %s", args=(self._url,)):
            resp = self._session.get(self._url, stream=False, timeout=self._timeout, headers=headers)

        if (code := resp.status_code) not in (200, 206):
            raise FileNotFoundError(
                f"Unable to read resource {self._url}, or bytes are out of range; status code: {code}"
            )

        # verify this is not actually the whole file and the server did not lie
        # about supporting ranges
        if len(resp.content) > size or code != 206:
            self._completeBuffer = io.BytesIO()
            self._completeBuffer.write(resp.content)
            self._completeBuffer.seek(0)
            return self.read(size=size)

        self._current_position += size
        return resp.content
