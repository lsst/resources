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

import http
import io
import logging
import sys
import threading
from collections.abc import Callable, Iterable
from http import HTTPStatus
from typing import TYPE_CHECKING, AnyStr

if sys.version_info >= (3, 12):
    from typing import override
else:
    from typing_extensions import override

import urllib3
from astropy import units as u

from lsst.utils.timer import time_this

from ..davutils import DavClient, DavClientDCache, redact_url
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
    file_size : `int`
        Size of the remote file, in bytes.
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
        *,
        newline: AnyStr | None = None,
    ) -> None:
        super().__init__(mode, log, uri, newline=newline)
        self._uri: DavResourcePath = uri
        self._client: DavClient = self._uri._client
        self._filesize: int = file_size
        self._closed = CloseStatus.OPEN
        self._current_position = 0
        self._cache: DavReadAheadCache = DavReadAheadCache(
            client=self._client,
            url=self._uri._internal_url,
            filesize=self._filesize,
            blocksize=self._uri._client._config.block_size,
            log=log,
        )
        self._lock = threading.Lock()
        self._log.debug("initializing read handle for %s [%#x]", self._uri, id(self))

    def close(self) -> None:
        with self._lock:
            if self._closed != CloseStatus.CLOSED:
                self._log.debug("closing read handle for %s [%#x]", self._uri, id(self))
                self._cache.close()
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
        with self._lock:
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
        with self._lock:
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
        The webDAV client to interact with the server to download data.
    url : `str`
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
        self, client: DavClient, url: str, filesize: int, blocksize: int, log: logging.Logger
    ) -> None:
        self._client: DavClient = client
        self._url: str = url
        self._filesize: int = filesize
        self._blocksize: int = blocksize
        self._cache = b""
        self._start: int = 0
        self._end: int = 0
        self._log: logging.Logger = log

        self._range_reader: DavRangeReader | DavDCacheRangeReader
        if isinstance(self._client, DavClientDCache):
            # Use a specialized range reader for dCache
            self._range_reader = DavDCacheRangeReader(
                self._client, self._url, self._filesize, self._blocksize, self._log
            )
        else:
            # Use a generic range reader
            self._range_reader = DavRangeReader(
                self._client, self._url, self._filesize, self._blocksize, self._log
            )

    def geturl(self) -> str:
        return redact_url(self._url)

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

        # Read the requested range.
        self._cache = self._range_reader.read_range(start=start_range, end=end_range - 1)
        self._start = start_range
        self._end = self._start + len(self._cache)
        return self._cache[start - self._start : end - self._start]

    def close(self) -> None:
        self._range_reader.close()


class DavRangeReader:
    """Helper reader of partial content of remote files.

    Parameters
    ----------
    client : `lsst.resources.davutils.DavClient`
        The webDAV client to interact with the server to download data.
    url : `str`
        URL of the resource to download data from.
    filesize : `int`
        Size in bytes of the remote file.
    blocksize : `int`
        Size in bytes of the block for this resource. This is the size we use
        to retrieve data from this resource.
    log : `logging.Logger`
        Logger object to emit log records.
    """

    def __init__(
        self, client: DavClient, url: str, filesize: int, blocksize: int, log: logging.Logger
    ) -> None:
        self._client: DavClient = client
        self._frontend_url: str = url
        self._backend_url: str = url
        self._filesize: int = filesize
        self._blocksize: int = blocksize
        self._log = log

    def __del__(self) -> None:
        self.close()

    def close(self) -> None:
        # The client's pool manager will reuse the underlying network
        # connection. There is nothing specific we need to do here.
        #
        # If that pool manager is configured to leave the networkf connections
        # open the connection will be reused, otherwise it will be closed.
        #
        # Keeping it open may be beneficial, in particular for XRootD servers
        # which require to use TLS with the back end servers. Other instances
        # of this class may use any of those reusable connections to contact
        # the same back end server, without needing to make the TLS handshake
        # again.
        pass

    def read_range(self, start: int, end: int) -> bytes:
        # No need to send a request if the file is empty.
        if self._filesize == 0:
            return b""

        # Use the WebDAV client to send a GET request with a Range header and
        # save the returned backend URL so that subsequent requests can
        # go directly to that server.
        #
        # This is beneficial when we are interacting with a XRootD server
        # which typically redirects requests to a data server. We want to
        # continue using that data server for subsequent requests without
        # going through the redirector.
        self._log.debug(f"reading range of file at {redact_url(self._backend_url)}: start={start} end={end}")
        self._backend_url, body = self._client.read_range(self._backend_url, start=start, end=end)
        return body


class DavDCacheRangeReader(DavRangeReader):
    # Docstring inherited.

    # This is a specialization of a DavRangeReader specifically for
    # interacting with a dCache server.
    #
    # Instances of this class open a network connection directly to the back
    # end server which serves the content of the file at `url`, keep that
    # connection open and use it to perform one or more partial read operations
    # of the file. Each of those operations is performed by issueing a
    # `GET` request with a `Range` header.

    # The important aspect of this behavior is that we choose not to directly
    # use the `DavClient` object to make those `GET` requests as the generic
    # DavRangeReader does, for two reasons.
    #
    # First, each of those requests would go first to the front end server
    # which would respond with a redirection to the back end server. That puts
    # unnecessary load on the dCache door for a slim benefit.
    #
    # Second, since the `DavClient` object uses a pool of network connections,
    # we cannot be sure that exactly the same network socket would be used
    # for sending all the `GET` requests for the same file.

    # For instance, in presence of multi-threading, the connection
    # pool manager of `DavClient` may choose to use another connection to send
    # that request. The dCache servers don't allow for that behavior: a
    # client can send several requests for the same file to the same back end
    # server provided that a single network connection is used for all those
    # requests. Once the network connection is closed, the client needs to go
    # through the door to get redirected again and dCache considers that is
    # a separate operation. That new operation will get a fresh
    # identifier which the client must send when interacting with the back
    # end server. The back end server verifies that that operation identifier
    # is valid, otherwise it redirects the client to the door.
    MAX_REDIRECTS: int = 3

    def __init__(
        self, client: DavClient, url: str, filesize: int, blocksize: int, log: logging.Logger
    ) -> None:
        super().__init__(client=client, url=url, filesize=filesize, blocksize=blocksize, log=log)
        self._conn: http.client.HTTPConnection | None = None
        self._scheme: str
        self._host: str
        self._port: int
        self._request_uri: str

    def __del__(self) -> None:
        self.close()

    def geturl(self) -> str:
        return redact_url(self._backend_url)

    def _reset_backend_url(self) -> None:
        self._backend_url = self._client._get_backend_url(self._frontend_url)

        url: urllib3.util.Url = urllib3.util.parse_url(self._backend_url)
        if (scheme := url.scheme) not in ("http", "https"):
            raise ValueError(f"Unexpected value {scheme} for scheme in URL {self.geturl()}")

        if (host := url.hostname) is None:
            raise ValueError(f"Unexpected value {host} in URL {self.geturl()}")

        if (port := url.port) is None:
            port = http.client.HTTPS_PORT if scheme == "https" else http.client.HTTP_PORT

        self._scheme = scheme
        self._host = host
        self._port = port
        self._request_uri = url.request_uri
        return

    def _reset_connection(self) -> None:
        # Close the existing connection, if any
        self.close()

        self._reset_backend_url()
        match self._scheme:
            case "http":
                self._conn = http.client.HTTPConnection(
                    host=self._host,
                    port=self._port,
                    timeout=self._client._config.timeout_connect,
                    blocksize=self._blocksize,
                )
            case "https":
                self._conn = http.client.HTTPSConnection(
                    host=self._host,
                    port=self._port,
                    timeout=self._client._config.timeout_connect,
                    blocksize=self._blocksize,
                    context=self._client._make_ssl_context(),
                )
            case _:
                pass

    @override
    def close(self) -> None:
        if self._conn is not None:
            try:
                # Send a "HEAD" request with "Connection: close" header
                # to notify the back end server we are no longer sending
                # requests
                resp = self._request("HEAD", headers={"Connection": "close"})
                resp.read()
            finally:
                self._log.debug(f"closing connection to {self.geturl()}")
                self._conn.close()
                self._conn = None

    def _request(self, method: str, headers: dict | None = None) -> http.client.HTTPResponse:
        # If not already done, establish the connection to the back end server.
        if self._conn is None:
            self._reset_connection()
            self._log.debug(f"connection was reset to {self.geturl()}")

        headers = {} if headers is None else dict(headers)
        headers.update({"Host": self._host})
        for attempt in range(1, DavDCacheRangeReader.MAX_REDIRECTS + 1):
            self._log.debug(
                "sending request (attempt %d/%d) %s %s",
                attempt,
                DavDCacheRangeReader.MAX_REDIRECTS,
                method,
                self.geturl(),
            )

            with time_this(
                self._log,
                msg="%s %s",
                args=(method, self.geturl()),
                mem_usage=self._client._config.collect_memory_usage,
                mem_unit=u.mebibyte,
            ):
                self._conn.request(method, self._request_uri, headers=headers)  # type: ignore[union-attr]
                resp: http.client.HTTPResponse = self._conn.getresponse()  # type: ignore[union-attr]
                match resp.status:
                    case HTTPStatus.TEMPORARY_REDIRECT:
                        # We got redirected. Reset the current connection and
                        # go again through the front end server to get
                        # redirected.
                        resp.read()
                        self._log.debug(
                            "GET request to %s got redirected to %s",
                            self.geturl(),
                            resp.getheader("Location"),
                        )
                        self._reset_connection()
                        continue
                    case _:
                        # We got a response from the backend server. Return it.
                        return resp

        raise ValueError(
            f"Reached maximum number of redirects ({DavDCacheRangeReader.MAX_REDIRECTS}) for "
            f"{self.geturl()}"
        )

    @override
    def read_range(self, start: int, end: int) -> bytes:
        # No need to send a request if the file is empty.
        if self._filesize == 0:
            return b""

        start = max(start, 0)
        end = min(self._filesize, end)
        self._log.debug(f"reading range of file at {self.geturl()}: start={start} end={end}")

        resp = self._request("GET", headers={"Range": f"bytes={start}-{end}"})
        match resp.status:
            case HTTPStatus.PARTIAL_CONTENT:
                return self._read_response_body(resp, self._filesize, start, end)
            case _:
                raise ValueError(f"unexpected response to GET request {resp.status} {resp.reason}")

    def _read_response_body(
        self, resp: http.client.HTTPResponse, file_size: int, range_start: int, range_end: int
    ) -> bytes:
        expected_content_length = f"{range_end - range_start + 1}"
        expected_content_range = f"bytes {range_start}-{range_end}/{file_size}"

        # Check that we got the expected headers with their expected values.
        if (content_range := resp.getheader("Content-Range")) is None:
            raise ValueError("Expecting value of 'Content-Range' header in response but got nothing")

        if (content_length := resp.getheader("Content-Length")) is None:
            raise ValueError("Expecting value of 'Content-Length' header in response but got nothing")

        if not content_length == expected_content_length or not content_range == expected_content_range:
            # Consume the response body
            resp.read()
            raise ValueError("Inconsistent value of 'Content-Range' or 'Content-Length' response headers")

        # Download the response body and verify its length is consistent with
        # the response headers.
        body = resp.read()
        if (body_length := len(body)) != int(content_length):
            raise ValueError(
                f"Value of 'Content-Length' response header '{content_length}' does not match "
                f"the actual length of response body ({body_length})"
            )

        self._log.debug("downloaded %d bytes from %s", body_length, self.geturl())
        return body
