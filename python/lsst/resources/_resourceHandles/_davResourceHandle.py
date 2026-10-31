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
        *,
        newline: AnyStr | None = None,
    ) -> None:
        super().__init__(mode, log, uri, newline=newline)
        self._client: DavClient = uri._client
        self._closed = CloseStatus.OPEN
        self._current_position = 0

        self._range_reader: DavRangeReader | DavDCacheRangeReader
        if isinstance(self._client, DavClientDCache):
            # Use a specialized range reader for dCache
            self._range_reader = DavDCacheRangeReader(
                client=self._client,
                url=uri._internal_url,
                blocksize=self._client._config.block_size,
                log=self._log,
            )
        else:
            # Use the generic range reader
            self._range_reader = DavRangeReader(
                client=self._client,
                url=uri._internal_url,
                blocksize=self._client._config.block_size,
                log=self._log,
            )

        # Retrieve this file size
        self._filesize: int = self._range_reader.filesize
        self._lock = threading.Lock()
        self._log.debug("initialized read handle for %s [%#x]", self._uri, id(self))

    def close(self) -> None:
        with self._lock:
            if self._closed != CloseStatus.CLOSED:
                self._log.debug("closing read handle for %s [%#x]", self._uri, id(self))
                self._range_reader.close()
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
        raise io.UnsupportedOperation("DavReadResourceHandles do not support truncation")

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

            output = self._range_reader.read_range(
                range_start=self._current_position, range_end=self._current_position + size
            )
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


class DavRangeReader:
    """Helper reader of partial content of remote files.

    Parameters
    ----------
    client : `lsst.resources.davutils.DavClient`
        The webDAV client to interact with the server to download data.
    url : `str`
        URL of the resource to download data from.
    blocksize : `int`
        Size in bytes of the block for this resource. This is the size we use
        to retrieve data from this resource.
    log : `logging.Logger`
        Logger object to emit log records.
    """

    def __init__(self, client: DavClient, url: str, blocksize: int, log: logging.Logger) -> None:
        self._client: DavClient = client
        self._frontend_url: str = url
        self._backend_url: str = url
        self._blocksize: int = blocksize
        self._log = log
        self._cache = b""
        self._cache_start: int = 0
        self._cache_end: int = 0
        self._filesize: int = -1  # Lazily initialized

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

    def geturl(self) -> str:
        return redact_url(self._backend_url)

    @property
    def filesize(self) -> int:
        if self._filesize >= 0:
            return self._filesize

        self._filesize = self._get_file_size()
        return self._filesize

    def read_range(self, range_start: int, range_end: int) -> bytes:
        """Fetch a chunk of the file and store it in memory.

        Parameters
        ----------
        range_start : `int`
            Position of the first byte of the chunk.
        range_end : `int`
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
            "DavRangeReader.read_range: %s range_start=%d range_end=%d [total: %d]",
            self.geturl(),
            range_start,
            range_end,
            range_end - range_start,
        )
        range_start = max(0, range_start)
        range_end = min(self._filesize, range_end)
        if range_start >= self._filesize or range_start > range_end:
            return b""

        if range_start >= self._cache_start and range_end <= self._cache_end:
            # The requested chunk is entirely cached.
            return self._cache[range_start - self._cache_start : range_end - self._cache_start]

        # The requested chunk is not fully in cache. Repopulate the cache
        # with a number of blocks large enough to include the requested chunk.
        blocks_to_fetch = 1 + ((range_end - range_start) // self._blocksize)
        bytes_to_fetch = self._blocksize * blocks_to_fetch
        end_fetch = min(self._filesize, range_start + bytes_to_fetch)
        start_fetch = max(0, end_fetch - bytes_to_fetch)

        self._log.debug(
            "populating read-ahead cache for handle of %s with %d blocks [%d - %d, total bytes: %d]",
            self.geturl(),
            blocks_to_fetch,
            start_fetch,
            end_fetch,
            end_fetch - start_fetch,
        )

        # Get the requested range from the remote server.
        self._cache = self._get_range(range_start=start_fetch, range_end=end_fetch - 1)
        self._cache_start = start_fetch
        self._cache_end = self._cache_start + len(self._cache)
        return self._cache[range_start - self._cache_start : range_end - self._cache_start]

    def _get_range(self, range_start: int, range_end: int) -> bytes:
        # Use the WebDAV client to send a 'GET' request with a 'Range' header
        # and save the returned backend URL so that subsequent requests can
        # go directly to that server.
        #
        # This is beneficial when we are interacting with a XRootD server
        # which typically redirects requests to a data server. We want to
        # continue using that data server for subsequent requests without
        # going through the redirector.
        self._log.debug(
            "reading range of file at %s: start=%d end=%d",
            redact_url(self._backend_url),
            range_start,
            range_end,
        )
        self._backend_url, body = self._client.read_range(self._backend_url, start=range_start, end=range_end)
        return body

    def _get_file_size(self) -> int:
        # Retrieve the size of this file from the remote server.
        return self._client.size(self._backend_url)


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
    # `DavRangeReader`` does, for two reasons.
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

    def __init__(self, client: DavClient, url: str, blocksize: int, log: logging.Logger) -> None:
        super().__init__(client=client, url=url, blocksize=blocksize, log=log)
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
                self._log.debug(f"closing connection to {self.geturl()}")
                self._conn.close()
            finally:
                self._conn = None

    @override
    def _get_file_size(self) -> int:
        # Send a HEAD request to the dCache pool to retrieve this file size.
        #
        # This is preferred to send the same HEAD request to the dCache door
        # because retrieving the size from the pool reduces the load on the
        # door when there are thousands of simultaneous clients openting
        # read handles.
        retry_policy = self._client._make_retry_policy()
        for attempt in retry_policy:
            resp = self._request("HEAD")
            resp.read()  # Read and discard response body
            match resp.status:
                case HTTPStatus.OK:
                    content_length = resp.getheader("Content-Length")
                    if content_length is not None:
                        return int(content_length)
                    else:
                        self._log.warning(
                            "Missing 'Content-Length' header in response to HEAD %s", self.geturl()
                        )
                case HTTPStatus.NOT_FOUND:
                    raise FileNotFoundError(f"No file found at {self._frontend_url}")
                case _:
                    # This is an unexpected status code. Retry the request.
                    self._log.warning(
                        "Unexpected response status %d %s to request HEAD %s [attempt %d/%d]",
                        resp.status,
                        resp.reason,
                        self.geturl(),
                        attempt,
                        retry_policy.max_attempts,
                    )

            # Wait and retry this request.
            retry_policy.wait()
            self._log.warning("Retrying request HEAD %s", self.geturl())

        # We exhausted the maximum number of attempts.
        raise ValueError(
            f"""Could not get a satisfactory response to request HEAD {self.geturl()} """
            f"""after {retry_policy.max_attempts} attempts"""
        )

    def _request(self, method: str, headers: dict | None = None) -> http.client.HTTPResponse:
        # If not already done, establish the connection to the back end server.
        if self._conn is None:
            self._reset_connection()
            self._log.debug(f"establishing connection for {self.geturl()}")

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
    def _get_range(self, range_start: int, range_end: int) -> bytes:
        self._log.debug(
            "reading range of file at %s: start=%d end=%d",
            self.geturl(),
            range_start,
            range_end,
        )

        headers = {
            "Accept-Encoding": "identity",
            "Range": f"bytes={range_start}-{range_end}",
        }
        retry_policy = self._client._make_retry_policy()
        for attempt in retry_policy:
            resp = self._request("GET", headers=headers)
            match resp.status:
                case HTTPStatus.PARTIAL_CONTENT:
                    # Check the response and retrieve the response body. A body
                    # with value `None` is a signal that we need to retry the
                    # request since the response we obtained is not
                    # as expected.
                    body = self._read_response_body(resp, self._filesize, range_start, range_end)
                    if body is not None:
                        return body
                case _:
                    # This is an unexpected status code. Discard the
                    # response body and retry the request.
                    resp.read()
                    self._log.warning(
                        """Unexpected response status %d %s to request GET %s (with header 'Range: %s') """
                        """[attempt %d/%d]""",
                        resp.status,
                        resp.reason,
                        self.geturl(),
                        headers.get("Range"),
                        attempt,
                        retry_policy.max_attempts,
                    )

            # Wait and retry this request.
            self._log.warning(
                "Retrying request GET %s (with header 'Range: %s')",
                self.geturl(),
                headers.get("Range"),
            )
            retry_policy.wait()

        # We exhausted the maximum number of attempts.
        raise ValueError(
            f"""Could not get a satisfactory response to request GET {self.geturl()} with header """
            f"""'Range: {headers.get("Range")}' after {retry_policy.max_attempts} attempts"""
        )

    def _read_response_body(
        self, resp: http.client.HTTPResponse, file_size: int, range_start: int, range_end: int
    ) -> bytes | None:
        # Download the response body.
        body = resp.read()
        body_length = len(body)

        # Check that we got response header `Content-Range` and that it has
        # the expected value.
        request_range_header = f"Range: bytes={range_start}-{range_end}"
        expected_content_range = f"bytes {range_start}-{range_end}/{file_size}"
        if (content_range := resp.getheader("Content-Range")) is None:
            self._log.warning(
                "Expected 'Content-Range' header in response to GET %s (with header '%s') is missing",
                self.geturl(),
                request_range_header,
            )
            return None

        if expected_content_range != content_range:
            self._log.warning(
                """Unexpected value of 'Content-Range' header in response to request GET %s """
                """(with header '%s'): expecting '%s' but got '%s'""",
                self.geturl(),
                request_range_header,
                expected_content_range,
                content_range,
            )
            return None

        # Check that we got response header `Content-Length` and that it has
        # the expected value.
        if (content_length := resp.getheader("Content-Length")) is None:
            self._log.warning(
                "Expected 'Content-Length' header in response to GET %s (with header '%s') is missing",
                self.geturl(),
                request_range_header,
            )
            return None

        expected_content_length = f"{range_end - range_start + 1}"
        if expected_content_length != content_length:
            self._log.warning(
                """Unexpected value of 'Content-Length' header in response to request GET %s """
                """(with header '%s'): expecting '%s' but got '%s'""",
                self.geturl(),
                request_range_header,
                expected_content_length,
                content_length,
            )
            return None

        # Check that the actual length of the response body matches the value
        # in the response header `Content-Length`.
        if body_length != int(content_length):
            self._log.warning(
                """Value of 'Content-Length' header in response to request GET %s """
                """(with header '%s') does not match the actual length of reponse body: """,
                """expecting '%d' but got '%s'""",
                self.geturl(),
                request_range_header,
                body_length,
                content_length,
            )

        self._log.debug("downloaded %d bytes from %s", body_length, self.geturl())
        return body
