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

__all__ = ("HttpResourcePath",)

import contextlib
import enum
import functools
import io
import json
import logging
import math
import os
import os.path
import random
import re
import ssl
import stat
import tempfile
from collections.abc import Iterator
from typing import TYPE_CHECKING, Any, BinaryIO, cast

try:
    # Prefer 'defusedxml' (not part of standard library) if available, since
    # 'xml' is vulnerable to XML bombs.
    import defusedxml.ElementTree as eTree
except ImportError:
    import xml.etree.ElementTree as eTree

try:
    import fsspec
    from aiohttp import ClientSession, TCPConnector
    from fsspec.implementations.http import HTTPFileSystem
    from fsspec.spec import AbstractFileSystem
except ImportError:
    fsspec = None
    AbstractFileSystem = type
    HTTPFileSystem = type

from urllib.parse import parse_qs

import requests
from astropy import units as u
from lsst.utils.timer import time_this
from requests.adapters import HTTPAdapter
from requests.auth import AuthBase
from urllib3.util.retry import Retry

from ._resourceHandles import ResourceHandleProtocol
from ._resourceHandles._httpResourceHandle import HttpReadResourceHandle, parse_content_range_header
from ._resourcePath import ResourcePath

if TYPE_CHECKING:
    from .utils import TransactionProtocol

log = logging.getLogger(__name__)


def _timeout_from_environment(env_var: str, default_value: float) -> float:
    """Convert and return a timeout from the value of an environment variable
    or a default value if the environment variable is not initialized. The
    value of `env_var` must be a valid `float` otherwise this function raises.

    Parameters
    ----------
    env_var : `str`
        Environment variable to look for.
    default_value : `float``
        Value to return if `env_var` is not defined in the environment.

    Returns
    -------
    _timeout_from_environment : `float`
        Converted value.
    """
    try:
        timeout = float(os.environ.get(env_var, default_value))
    except ValueError:
        raise ValueError(
            f"Expecting valid timeout value in environment variable {env_var} but found "
            f"{os.environ.get(env_var)}"
        ) from None

    if math.isnan(timeout):
        raise ValueError(f"Unexpected timeout value NaN found in environment variable {env_var}")

    return timeout


class HttpResourcePathConfig:
    """Configuration class to encapsulate the configurable items used by class
    HttpResourcePath.
    """

    # Default timeouts for all HTTP requests (seconds).
    DEFAULT_TIMEOUT_CONNECT: float = 30.0
    DEFAULT_TIMEOUT_READ: float = 1_500.0

    # Default lower and upper bounds for the backoff interval (seconds).
    # A value in this interval is randomly selected as the backoff factor when
    # requests need to be retried.
    DEFAULT_BACKOFF_MIN: float = 1.0
    DEFAULT_BACKOFF_MAX: float = 3.0

    # Default number of connections to persist with both the front end and
    # back end servers.
    DEFAULT_FRONTEND_PERSISTENT_CONNECTIONS: int = 2
    DEFAULT_BACKEND_PERSISTENT_CONNECTIONS: int = 1

    # Accepted digest algorithms
    ACCEPTED_DIGESTS: list[str] = ["adler32", "md5", "sha-256", "sha-512"]

    def __init__(self) -> None:
        self._front_end_connections: int | None = None
        self._back_end_connections: int | None = None
        self._digest_algorithm: str | None = None
        self._send_expect_on_put: bool | None = None
        self._timeout: tuple[float, float] | None = None
        self._collect_memory_usage: bool | None = None
        self._backoff_min: float | None = None
        self._backoff_max: float | None = None
        self._ca_bundle: str | None = ""
        self._client_token: str | None = ""
        self._client_cert: str | None = ""
        self._client_key: str | None = ""
        self._tmpdir_buffersize: tuple[str, int] | None = None
        self._ssl_context: ssl.SSLContext | None = None

    @property
    def front_end_connections(self) -> int:
        """Number of persistent connections to the front end server."""
        if self._front_end_connections is not None:
            return self._front_end_connections

        try:
            self._front_end_connections = int(
                os.environ.get(
                    "LSST_HTTP_FRONTEND_PERSISTENT_CONNECTIONS", self.DEFAULT_FRONTEND_PERSISTENT_CONNECTIONS
                )
            )
        except ValueError:
            self._front_end_connections = self.DEFAULT_FRONTEND_PERSISTENT_CONNECTIONS

        return self._front_end_connections

    @property
    def back_end_connections(self) -> int:
        """Number of persistent connections to the back end servers."""
        if self._back_end_connections is not None:
            return self._back_end_connections

        try:
            self._back_end_connections = int(
                os.environ.get(
                    "LSST_HTTP_BACKEND_PERSISTENT_CONNECTIONS", self.DEFAULT_BACKEND_PERSISTENT_CONNECTIONS
                )
            )
        except ValueError:
            self._back_end_connections = self.DEFAULT_BACKEND_PERSISTENT_CONNECTIONS

        return self._back_end_connections

    @property
    def digest_algorithm(self) -> str:
        """Algorithm to ask the server to use for computing and recording
        digests of each file contents in PUT requests.

        Returns
        -------
        digest_algorithm: `str`
            The name of a digest algorithm or the empty string if no algotihm
            is configured.
        """
        if self._digest_algorithm is not None:
            return self._digest_algorithm

        digest = os.environ.get("LSST_HTTP_DIGEST", "").lower()
        if digest not in self.ACCEPTED_DIGESTS:
            digest = ""

        self._digest_algorithm = digest
        return self._digest_algorithm

    @property
    def send_expect_on_put(self) -> bool:
        """Return True if a "Expect: 100-continue" header is to be sent to
        the server on each PUT request.

        Some servers (e.g. dCache) uses this information as an indication that
        the client knows how to handle redirects to the specific server that
        will actually receive the data for PUT requests.
        """
        if self._send_expect_on_put is not None:
            return self._send_expect_on_put

        self._send_expect_on_put = "LSST_HTTP_PUT_SEND_EXPECT_HEADER" in os.environ
        return self._send_expect_on_put

    @property
    def timeout(self) -> tuple[float, float]:
        """Return a tuple with the values of timeouts for connecting to the
        server and reading its response, respectively. Both values are in
        seconds.
        """
        if self._timeout is not None:
            return self._timeout

        self._timeout = (
            _timeout_from_environment("LSST_HTTP_TIMEOUT_CONNECT", self.DEFAULT_TIMEOUT_CONNECT),
            _timeout_from_environment("LSST_HTTP_TIMEOUT_READ", self.DEFAULT_TIMEOUT_READ),
        )
        return self._timeout

    @property
    def collect_memory_usage(self) -> bool:
        """Return true if we want to collect memory usage when timing
        operations against the remote server via the `lsst.utils.time_this`
        context manager.
        """
        if self._collect_memory_usage is not None:
            return self._collect_memory_usage

        self._collect_memory_usage = "LSST_HTTP_COLLECT_MEMORY_USAGE" in os.environ
        return self._collect_memory_usage

    @property
    def backoff_min(self) -> float:
        """Lower bound of the interval from which a backoff factor is randomly
        selected when retrying requests (seconds).
        """
        if self._backoff_min is not None:
            return self._backoff_min

        self._backoff_min = self.DEFAULT_BACKOFF_MIN
        try:
            backoff_min = float(os.environ.get("LSST_HTTP_BACKOFF_MIN", self.DEFAULT_BACKOFF_MIN))
            if not math.isnan(backoff_min):
                self._backoff_min = backoff_min
        except ValueError:
            pass

        return self._backoff_min

    @property
    def backoff_max(self) -> float:
        """Upper bound of the interval from which a backoff factor is randomly
        selected when retrying requests (seconds).
        """
        if self._backoff_max is not None:
            return self._backoff_max

        self._backoff_max = self.DEFAULT_BACKOFF_MAX
        try:
            backoff_max = float(os.environ.get("LSST_HTTP_BACKOFF_MAX", self.DEFAULT_BACKOFF_MAX))
            if not math.isnan(backoff_max):
                self._backoff_max = backoff_max
        except ValueError:
            pass

        return self._backoff_max

    @property
    def ca_bundle(self) -> str | None:
        """Local path to the certificate bundle file or directory where the
        certifcates of the trusted authorities are located.

        Return None if this host's system certificate bundle should be
        used for authenticating remote servers' certificates.
        """
        if self._ca_bundle != "":
            return self._ca_bundle

        # If a bundle was specified via the environment variable
        # 'LSST_HTTP_CACERT_BUNDLE' use it.
        self._ca_bundle = os.getenv("LSST_HTTP_CACERT_BUNDLE")
        return self._ca_bundle

    @property
    def client_token(self) -> str | None:
        """Value of a bearer token or path to a local file which contains
        the bearer token to use for authenticating the client when sending
        requests to the webDAV or HTTP server.

        Return None if no bearer token is configured in the environment.
        """
        if self._client_token != "":
            return self._client_token

        # If environment variable LSST_HTTP_AUTH_BEARER_TOKEN is
        # initialized use its value as the bearer token.
        self._client_token = os.getenv("LSST_HTTP_AUTH_BEARER_TOKEN")
        return self._client_token

    @property
    def client_cert_key(self) -> tuple[str | None, str | None]:
        """Paths to a local file where the client certificate and associated
        private key are located.

        Return a tuple (client certificate, private key) or (None, None) if no
        client certificate is configured via environment variables.
        """
        if self._client_cert != "" and self._client_key != "":
            return (self._client_cert, self._client_key)

        # If the environment variables LSST_HTTP_AUTH_CLIENT_CERT
        # and LSST_HTTP_AUTH_CLIENT_KEY are initialized use their values.
        self._client_cert = os.getenv("LSST_HTTP_AUTH_CLIENT_CERT")
        self._client_key = os.getenv("LSST_HTTP_AUTH_CLIENT_KEY")
        if self._client_cert and self._client_key:
            if not _is_protected(self._client_key):
                raise PermissionError(
                    f"Private key file at {self._client_key} must be protected for access only by its owner"
                )
            return (self._client_cert, self._client_key)

        # If only the certificate was provided raise.
        if self._client_cert:
            raise ValueError(
                "Environment variable LSST_HTTP_AUTH_CLIENT_KEY must be set to client private key file path"
            )

        # If only the private key was provided raise.
        if self._client_key:
            raise ValueError(
                "Environment variable LSST_HTTP_AUTH_CLIENT_CERT must be set to client certificate file path"
            )

        # If a X.509 user proxy is available, use it as client credentials.
        self._client_cert = self._client_key = os.getenv("X509_USER_PROXY")
        return (self._client_cert, self._client_key)

    @property
    def tmpdir_buffersize(self) -> tuple[str, int]:
        """Return the path to a temporary directory and the preferred buffer
        size to use when reading or writing files in that directory.
        """
        if self._tmpdir_buffersize is not None:
            return self._tmpdir_buffersize

        # Use the value of environment variables 'LSST_RESOURCES_TMPDIR' or
        # 'TMPDIR', if defined. Otherwise use the system temporary directory,
        # with a last-resort fallback to the current working directory if
        # nothing else is available.
        tmpdir = None
        for dir in (os.getenv(v) for v in ("LSST_RESOURCES_TMPDIR", "TMPDIR")):
            if dir and os.path.isdir(dir):
                tmpdir = dir
                break

        if tmpdir is None:
            tmpdir = tempfile.gettempdir()

        # Compute the block size as 256 blocks of typical size
        # (i.e. 4096 bytes) or 10 times the file system block size,
        # whichever is higher. This is a reasonable compromise between
        # using memory for buffering and the number of system calls
        # issued to read from or write to temporary files.
        fsstats = os.statvfs(tmpdir)
        self._tmpdir_buffersize = (tmpdir, max(10 * fsstats.f_bsize, 256 * 4096))

        return self._tmpdir_buffersize

    @property
    def ssl_context(self) -> ssl.SSLContext:
        """Return an SSL context equiped with the certificates of the trusted
        authorities.
        """
        if self._ssl_context is None:
            self._ssl_context = ssl.create_default_context()
            if self.ca_bundle is not None:
                if os.path.isdir(self.ca_bundle):
                    self._ssl_context.load_verify_locations(capath=self.ca_bundle)
                elif os.path.isfile(self.ca_bundle):
                    self._ssl_context.load_verify_locations(cafile=self.ca_bundle)

        return self._ssl_context


@functools.lru_cache
def _get_dav_and_server_headers(path: ResourcePath | str) -> tuple[str | None, str | None]:
    """Retrieve the "DAV" and "Server" headers sent by the remote server as
    part of the response to a single "OPTIONS" HTTP request.

    Parameters
    ----------
    path : `ResourcePath` or `str`
        URL to the resource to be checked.
        Should preferably refer to the root since the status is shared
        by all paths in that server.

    Returns
    -------
    _get_dav_and_server_headers : `tuple[str|None, str|None]`
        Values of the "DAV" and "Server" headers found in the response or
        None if any of those headers was not part of the response.
    """
    try:
        if not isinstance(path, HttpResourcePath):
            path = HttpResourcePath(path)

        config = HttpResourcePathConfig()
        with SessionStore(config=config).get(path) as session:
            resp = session.options(
                str(path),
                stream=False,
                timeout=config.timeout,
            )

            dav_header = server_header = None
            if resp.status_code == requests.codes.ok:
                dav_header = resp.headers.get("DAV") if "DAV" in resp.headers else None
                server_header = resp.headers.get("Server") if "Server" in resp.headers else None

            return (dav_header, server_header)

    except requests.exceptions.SSLError as e:
        log.warning(
            "Environment variable LSST_HTTP_CACERT_BUNDLE can be used to "
            "specify the path to a bundle of certificate authorities you trust "
            "which are not included in the default set of trusted authorities "
            "of this system."
        )
        raise e


class BearerTokenAuth(AuthBase):
    """Attach a bearer token 'Authorization' header to each request.

    Parameters
    ----------
    token : `str`
        Can be either the path to a local protected file which contains the
        value of the token or the token itself.
    """

    def __init__(self, token: str):
        self._token = self._path = None
        self._mtime: float = -1.0
        if not token:
            return

        self._token = token
        if os.path.isfile(token):
            self._path = os.path.abspath(token)
            if not _is_protected(self._path):
                raise PermissionError(
                    f"Bearer token file at {self._path} must be protected for access only by its owner"
                )
            self._refresh()

    def _refresh(self) -> None:
        """Read the token file (if any) if its modification time is more recent
        than the last time we read it.
        """
        if not self._path:
            return

        if (mtime := os.stat(self._path).st_mtime) > self._mtime:
            log.debug("Reading bearer token file at %s", self._path)
            self._mtime = mtime
            with open(self._path) as f:
                self._token = f.read().rstrip("\n")

    def __call__(self, req: requests.PreparedRequest) -> requests.PreparedRequest:
        # Only add a bearer token to a request when using secure HTTP.
        if req.url and req.url.lower().startswith("https://") and self._token:
            self._refresh()
            req.headers["Authorization"] = f"Bearer {self._token}"
        return req


class SessionStore:
    """Cache a reusable HTTP client session per endpoint.

    Parameters
    ----------
    config : `HttpResourcePathConfig`
        Configuration items shared by all instances of HttpResourcePath.
    num_pools : `int`, optional
        Number of connection pools to keep: there is one pool per remote
        host.
    max_persistent_connections : `int`, optional
        Maximum number of connections per remote host to persist in each
        connection pool.
    backoff_min : `float`, optional
        Minimum value of the interval to compute the exponential
        backoff factor when retrying requests (seconds).
    backoff_max : `float`, optional
        Maximum value of the interval to compute the exponential
        backoff factor when retrying requests (seconds).
    """

    def __init__(
        self,
        config: HttpResourcePathConfig,
        num_pools: int = 10,
        max_persistent_connections: int = 1,
        backoff_min: float = 1.0,
        backoff_max: float = 3.0,
    ) -> None:
        # Dictionary to store the session associated to a given URI. The key
        # of the dictionary is a root URI and the value is the session.
        self._sessions: dict[str, requests.Session] = {}

        # Configuration for all instances of HttpResourcePath objects.
        self._config = config

        # See documentation of urllib3 PoolManager class:
        # https://urllib3.readthedocs.io
        self._num_pools: int = num_pools

        # See urllib3 Advanced Usage documentation:
        # https://urllib3.readthedocs.io/en/stable/advanced-usage.html
        self._max_persistent_connections: int = max_persistent_connections

        # Minimum and maximum values of the interval to compute the exponential
        # backoff factor when retrying requests (seconds).
        self._backoff_min: float = backoff_min
        self._backoff_max: float = backoff_max if backoff_max > backoff_min else backoff_min + 1.0

    def clear(self) -> None:
        """Destroy all previously created sessions and attempt to close
        underlying idle network connections.
        """
        # Close all sessions and empty the store. Idle network connections
        # should be closed as a consequence. We don't have means through
        # the API exposed by Requests to actually force closing the
        # underlying open sockets.
        for session in self._sessions.values():
            session.close()

        self._sessions.clear()

    def get(self, rpath: ResourcePath) -> requests.Session:
        """Retrieve a session for accessing the remote resource at rpath.

        Parameters
        ----------
        rpath : `ResourcePath`
            URL to a resource at the remote server for which a session is to
            be retrieved.

        Notes
        -----
        Once a session is created for a given endpoint it is cached and
        returned every time a session is requested for any path under that same
        endpoint. For instance, a single session will be cached and shared
        for paths "https://www.example.org/path/to/file" and
        "https://www.example.org/any/other/path".

        Note that "https://www.example.org" and "https://www.example.org:12345"
        will have different sessions since the port number is not identical.
        """
        root_uri = str(rpath.root_uri())
        if root_uri not in self._sessions:
            # We don't have yet a session for this endpoint: create a new one.
            self._sessions[root_uri] = self._make_session(rpath)

        return self._sessions[root_uri]

    def _make_session(self, rpath: ResourcePath) -> requests.Session:
        """Make a new session configured from values from the environment."""
        session = requests.Session()
        root_uri = str(rpath.root_uri())
        log.debug("Creating new HTTP session for endpoint %s ...", root_uri)
        retries = Retry(
            # Total number of retries to allow. Takes precedence over other
            # counts.
            total=6,
            # How many connection-related errors to retry on.
            connect=3,
            # How many times to retry on read errors.
            read=3,
            # Backoff factor to apply between attempts after the second try
            # (seconds). Compute a random jitter to prevent all the clients
            # to overwhelm the server by sending requests at the same time.
            backoff_factor=self._backoff_min + (self._backoff_max - self._backoff_min) * random.random(),
            # How many times to retry on bad status codes.
            status=5,
            # Set of uppercased HTTP method verbs that we should retry on.
            # We only automatically retry idempotent requests.
            allowed_methods=frozenset(
                [
                    "COPY",
                    "DELETE",
                    "GET",
                    "HEAD",
                    "MKCOL",
                    "OPTIONS",
                    "PROPFIND",
                    "PUT",
                ]
            ),
            # HTTP status codes that we should force a retry on.
            status_forcelist=frozenset(
                [
                    requests.codes.too_many_requests,  # 429
                    requests.codes.internal_server_error,  # 500
                    requests.codes.bad_gateway,  # 502
                    requests.codes.service_unavailable,  # 503
                    requests.codes.gateway_timeout,  # 504
                ]
            ),
            # Whether to respect Retry-After header on status codes defined
            # above.
            respect_retry_after_header=True,
        )

        # Persist the specified number of connections to the front end server.
        session.mount(
            root_uri,
            HTTPAdapter(
                pool_connections=self._num_pools,
                pool_maxsize=self._max_persistent_connections,
                pool_block=False,
                max_retries=retries,
            ),
        )

        # Do not persist the connections to back end servers which may vary
        # from request to request. Systematically persisting connections to
        # those servers may exhaust their capabilities when there are thousands
        # of simultaneous clients.
        session.mount(
            f"{rpath.scheme}://",
            HTTPAdapter(
                pool_connections=self._num_pools,
                pool_maxsize=0,
                pool_block=False,
                max_retries=retries,
            ),
        )

        # If the remote endpoint doesn't use secure HTTP we don't include
        # bearer tokens in the requests nor need to authenticate the remote
        # server.
        if rpath.scheme != "https":
            return session

        # Set the trusted CA certificates bundle for authenticating remote
        # servers.
        session.verify = True if self._config.ca_bundle is None else self._config.ca_bundle

        # Should we use a bearer token for client authentication?
        if (token := self._config.client_token) is not None:
            log.debug("... using bearer token authentication")
            session.auth = BearerTokenAuth(token)
            return session

        # Should we instead use client certificate and private key?
        client_cert, client_key = self._config.client_cert_key
        if client_cert and client_key:
            log.debug("... using client certificate authentication.")
            session.cert = (client_cert, client_key)
            return session

        log.debug(
            "Neither LSST_HTTP_AUTH_BEARER_TOKEN nor (LSST_HTTP_AUTH_CLIENT_CERT and "
            "LSST_HTTP_AUTH_CLIENT_KEY) are initialized. Client authentication is disabled."
        )
        return session


class ActivityCaveat(enum.Enum):
    """Helper class for enumerating accepted activity caveats for requesting
    macaroons.
    """

    DOWNLOAD = 1
    UPLOAD = 2


class HttpResourcePath(ResourcePath):
    """General HTTP(S) resource.

    Notes
    -----
    In order to configure the behavior of instances of this class, the
    environment variables below are inspected:

    - LSST_HTTP_CACERT_BUNDLE: path to a .pem file or to a directory which
        contains the .pem files of the trusted certificate authorities's
        certificates. If the remote server presents a server certificate
        issued by one of those trusted authorities, we trust it.
        If this environment variable is not initialized, the default
        authorities of the the execution host are trusted.

    - LSST_HTTP_AUTH_BEARER_TOKEN: value of a bearer token or path to a
        local file containing a bearer token to be used as the client
        authentication mechanism with all requests.
        The permissions of the token file must be set so that only its
        owner can access it.
        If initialized, takes precedence over LSST_HTTP_AUTH_CLIENT_CERT
        and LSST_HTTP_AUTH_CLIENT_KEY.

    - LSST_HTTP_AUTH_CLIENT_CERT: path to a .pem file which contains the
        client certificate for authenticating to the server.
        If initialized, the variable LSST_HTTP_AUTH_CLIENT_KEY must also be
        initialized with the path of the client private key file.
        The permissions of the client private key must be set so that only
        its owner can access it, at least for reading.

    - LSST_HTTP_PUT_SEND_EXPECT_HEADER: if set (with any value), a
        "Expect: 100-Continue" header will be added to all HTTP PUT requests.
        This header is required by some servers to detect if the client
        knows how to handle redirections. In case of redirection, the body
        of the PUT request is sent to the redirected location and not to
        the front end server.

    - LSST_HTTP_TIMEOUT_CONNECT and LSST_HTTP_TIMEOUT_READ: if set to a
        numeric value, they are interpreted as the number of seconds to wait
        for establishing a connection with the server and for reading its
        response, respectively.

    - LSST_HTTP_FRONTEND_PERSISTENT_CONNECTIONS and
        LSST_HTTP_BACKEND_PERSISTENT_CONNECTIONS: contain the maximum number
        of connections to attempt to persist with both the front end servers
        and the back end servers.
        Default values: DEFAULT_FRONTEND_PERSISTENT_CONNECTIONS and
        DEFAULT_BACKEND_PERSISTENT_CONNECTIONS.

    - LSST_HTTP_DIGEST: case-insensitive name of the digest algorithm to
        ask the server to compute for every file's content sent to the server
        via a PUT request. No digest is requested if this variable is not set
        or is set to an invalid value.
        Valid values are those in ACCEPTED_DIGESTS.
    """

    # WebDAV servers known to be able to sign URLs. The values are lowercased
    # server identifiers retrieved from the 'Server' header included in
    # the response to a HTTP OPTIONS request.
    SUPPORTED_URL_SIGNERS = ("dcache", "xrootd")

    # Configuration items for this class instances.
    _config = HttpResourcePathConfig()

    # The session for metadata requests is used for interacting with
    # the front end servers for requests such as PROPFIND, HEAD, etc. Those
    # interactions are typically served by the front end servers. We want to
    # keep the connection to the front end servers open, to reduce the cost
    # associated to TCP and TLS handshaking for each new request.
    _metadata_session_store = SessionStore(
        config=_config,
        num_pools=5,
        max_persistent_connections=_config.front_end_connections,
        backoff_min=_config.backoff_min,
        backoff_max=_config.backoff_max,
    )

    # The data session is used for interaction with the front end servers which
    # typically redirect to the back end servers for serving our PUT and GET
    # requests. We attempt to keep a single connection open with the front end
    # server, if possible. This depends on how the server behaves and the
    # kind of request. Some servers close the connection when redirecting
    # the client to a back end server, for instance when serving a PUT
    # request.
    _data_session_store = SessionStore(
        config=_config,
        num_pools=25,
        max_persistent_connections=_config.back_end_connections,
        backoff_min=_config.backoff_min,
        backoff_max=_config.backoff_max,
    )

    # Process ID which created the session stores above. We need to store this
    # to replace sessions created by a parent process and inherited by a
    # child process after a fork, to avoid confusing the SSL layer.
    _pid: int = -1

    # Connector used by a session pool to establish network connections to
    # remote servers. This connector is exclusively used by fsspec file system
    # and is shared by all instances of this class.
    _tcp_connector: TCPConnector | None = None

    @property
    def metadata_session(self) -> requests.Session:
        """Client session to send requests which do not require upload or
        download of data, i.e. mostly metadata requests.
        """
        if hasattr(self, "_metadata_session"):
            if HttpResourcePath._pid == os.getpid():
                return self._metadata_session
            else:
                # The metadata session we have in cache was likely created by
                # a parent process. Discard all the sessions in that store.
                self._metadata_session_store.clear()

        # Retrieve a new metadata session.
        HttpResourcePath._pid = os.getpid()
        self._metadata_session: requests.Session = self._metadata_session_store.get(self)
        return self._metadata_session

    @property
    def data_session(self) -> requests.Session:
        """Client session for uploading and downloading data."""
        if hasattr(self, "_data_session"):
            if HttpResourcePath._pid == os.getpid():
                return self._data_session
            else:
                # The data session we have in cache was likely created by
                # a parent process. Discard all the sessions in that store.
                self._data_session_store.clear()

        # Retrieve a new data session.
        HttpResourcePath._pid = os.getpid()
        self._data_session: requests.Session = self._data_session_store.get(self)
        return self._data_session

    def _clear_sessions(self) -> None:
        """Close the socket connections that are still open.

        Used only in test suites to avoid warnings.
        """
        self._metadata_session_store.clear()
        self._data_session_store.clear()

        if hasattr(self, "_metadata_session"):
            delattr(self, "_metadata_session")

        if hasattr(self, "_data_session"):
            delattr(self, "_data_session")

    def _init_server_properties(self) -> None:
        """
        Initialize instance variables '_is_webdav' and '_server' by
        sending a single OPTIONS request to the remote server and
        saving the results.
        """
        # Retrieve the "DAV" and the "Server" headers for the root URL of this
        # path
        dav_header, server_header = _get_dav_and_server_headers(self.root_uri())

        # Check that "1" is part of the value of the "DAV" header. We don't
        # use locks, so a server complying to class 1 is enough for our
        # purposes. All webDAV servers must advertise at least compliance
        # class "1".
        #
        # Compliance classes are documented in
        #    http://www.webdav.org/specs/rfc4918.html#dav.compliance.classes
        #
        # Examples of values for header DAV are:
        #   DAV: 1, 2
        #   DAV: 1, <http://apache.org/dav/propset/fs/1>
        self._is_webdav: bool = False
        if dav_header is not None:
            self._is_webdav = "1" in dav_header.replace(" ", "").split(",")

        self._server: str | None = None
        if server_header is not None:
            # Server header is expected to be of the form 'dCache/9.2.4'
            # or 'XrootD/v5.7.1'. Strip version and put in lowercase.
            self._server = server_header.split("/")[0].lower()

    @property
    def is_webdav_endpoint(self) -> bool:
        """Check if the current endpoint implements WebDAV features.

        This is stored per URI but cached by root so there is only one check
        per hostname.
        """
        if hasattr(self, "_is_webdav"):
            return self._is_webdav

        self._init_server_properties()
        return self._is_webdav

    @property
    def server(self) -> str | None:
        """Return the lowercased identifier of the remote server, retrieved
        from the response header 'Server' from an 'OPTIONS' HTTP request.

        If the remote server does not include that header in its response
        to an 'OPTIONS' request, server() returns None.

        Examples of return values are "dcache", "xrootd".
        """
        if hasattr(self, "_server"):
            return self._server

        self._init_server_properties()
        return self._server

    @property
    def server_signs_urls(self) -> bool:
        """Return true if the remote server support signing or URLs for
        download and upload.
        """
        return self.server in HttpResourcePath.SUPPORTED_URL_SIGNERS

    def exists(self) -> bool:
        """Check that a remote HTTP resource exists."""
        log.debug("Checking if resource exists: %s", self.geturl())
        if not self.is_webdav_endpoint:
            # The remote is a plain HTTP server. Let's attempt a HEAD
            # request, even if the behavior for such a request against a
            # directory is not specified, so it depends on the server
            # implementation.
            resp = self._head_non_webdav_url()
            return self._is_successful_non_webdav_head_request(resp)

        # The remote endpoint is a webDAV server: send a PROPFIND request
        # to determine if it exists.
        resp = self._propfind()
        if resp.status_code == requests.codes.multi_status:  # 207
            prop = _parse_propfind_response_body(resp.text)[0]
            return prop.exists
        else:  # 404 Not Found
            return False

    def size(self) -> int:
        """Return the size of the remote resource in bytes."""
        if self.dirLike:
            return 0

        if not self.is_webdav_endpoint:
            # The remote is a plain HTTP server. Send a HEAD request to
            # retrieve the size of the resource.
            resp = self._head_non_webdav_url()
            if resp.status_code == requests.codes.ok:  # 200
                if "Content-Length" in resp.headers:
                    return int(resp.headers["Content-Length"])
                else:
                    raise ValueError(
                        f"Response to HEAD request to {self} does not contain 'Content-Length' header"
                    )
            elif resp.status_code == requests.codes.partial_content:
                # 206 Partial Content, returned from a GET request with a Range
                # header (used to emulate HEAD for presigned S3 URLs).
                # In this case Content-Length is the length of the Range and
                # not the full length of the file, so we have to parse
                # Content-Range instead.
                content_range_header = resp.headers.get("Content-Range")
                if content_range_header is None:
                    raise ValueError(
                        f"Response to GET request to {self} did not contain 'Content-Range' header"
                    )
                content_range = parse_content_range_header(content_range_header)
                size = content_range.total
                if size is None:
                    raise ValueError(f"Content-Range header for {self} did not include a total file size")
                return size
            elif resp.status_code == requests.codes.range_not_satisfiable:
                # 416 Range Not Satisfiable, which can occur on a GET for a 0
                # byte file since we asked for 1 byte Range which is longer
                # than the file.
                #
                # Servers are supposed to include a Content-Range header in
                # this case, but Google's S3 implementation doesn't.  Any
                # non-zero file size should have been handled by the 206 and
                # 200 cases above, so assume we have a zero here.
                return 0
            elif resp.status_code == requests.codes.not_found:
                raise FileNotFoundError(
                    f"Resource {self} does not exist, status: {resp.status_code} {resp.reason}"
                )
            else:
                raise ValueError(
                    f"Unexpected response for HEAD request for {self}, status: {resp.status_code} "
                    f"{resp.reason}"
                )

        # The remote is a webDAV server: send a PROPFIND request to retrieve
        # the size of the resource. Sizes are only meaningful for files.
        resp = self._propfind()
        if resp.status_code == requests.codes.multi_status:  # 207
            prop = _parse_propfind_response_body(resp.text)[0]
            if prop.is_file:
                return prop.size
            elif prop.is_directory:
                raise IsADirectoryError(
                    f"Resource {self} is reported by server as a directory but has a file path"
                )
            else:
                raise FileNotFoundError(f"Resource {self} does not exist")
        else:  # 404 Not Found
            raise FileNotFoundError(
                f"Resource {self} does not exist, status: {resp.status_code} {resp.reason}"
            )

    def _head_non_webdav_url(self) -> requests.Response:
        """Return a response from a HTTP HEAD request for a non-WebDAV HTTP
        URL.

        Emulates HEAD using a 1-byte GET for presigned S3 URLs.
        """
        if self._looks_like_presigned_s3_url():
            # Presigned S3 URLs are signed for a single method only, so you
            # can't call HEAD on a URL signed for GET.   However, S3 does
            # support Range requests, so you can ask for a 1-byte range with
            # GET for a similar effect to HEAD.
            #
            # Note that some headers differ between a true HEAD request and the
            # response returned by this GET, e.g. Content-Length will always be
            # 1, and the status code is 206 instead of 200.
            return self.metadata_session.get(
                self.geturl(),
                timeout=self._config.timeout,
                allow_redirects=True,
                stream=False,
                headers={"Range": "bytes=0-0"},
            )
        else:
            return self.metadata_session.head(
                self.geturl(), timeout=self._config.timeout, allow_redirects=True, stream=False
            )

    def _is_successful_non_webdav_head_request(self, resp: requests.Response) -> bool:
        """Return `True` if the status code in the response indicates a
        successful response to ``_head_non_webdav_url``.
        """
        return resp.status_code in (
            requests.codes.ok,  # 200, from a normal HEAD or GET request
            requests.codes.partial_content,  # 206, returned from a GET request with a Range header.
            # 416, returned from a GET request with a 1-byte Range header that
            # is longer than the 0-byte file.
            requests.codes.range_not_satisfiable,
        )

    def _looks_like_presigned_s3_url(self) -> bool:
        """Return `True` if this ResourcePath's URL is likely to be a presigned
        S3 URL.
        """
        query_params = parse_qs(self._uri.query)
        return "Signature" in query_params and "Expires" in query_params

    def mkdir(self) -> None:
        """Create the directory resource if it does not already exist."""
        # Creating directories is only available on WebDAV back ends.
        if not self.is_webdav_endpoint:
            raise NotImplementedError(
                f"Creation of directory {self} is not implemented by plain HTTP servers"
            )

        if not self.dirLike:
            raise NotADirectoryError(f"Can not create a 'directory' for file-like URI {self}")

        # Check if the target directory already exists.
        resp = self._propfind()
        if resp.status_code == requests.codes.multi_status:  # 207
            prop = _parse_propfind_response_body(resp.text)[0]
            if prop.exists:
                if prop.is_directory:
                    return
                else:
                    # A file exists at this path
                    raise NotADirectoryError(
                        f"Can not create a directory for {self} because a file already exists at that path"
                    )

        # Target directory does not exist. Create it and its ancestors as
        # needed. We need to test if parent URL is different from self URL,
        # otherwise we could be stuck in a recursive loop
        # where self == parent.
        if self.geturl() != self.parent().geturl():
            self.parent().mkdir()

        log.debug("Creating new directory: %s", self.geturl())
        self._mkcol()

    def remove(self) -> None:
        """Remove the resource."""
        self._delete()

    def read(self, size: int = -1) -> bytes:
        """Open the resource and return the contents in bytes.

        Parameters
        ----------
        size : `int`, optional
            The number of bytes to read. Negative or omitted indicates
            that all data should be read.
        """
        # Use the data session as a context manager to ensure that the
        # network connections to both the front end and back end servers are
        # closed after downloading the data.
        log.debug("Reading from remote resource: %s", self.geturl())
        stream = size > 0
        with self.data_session as session:
            with time_this(log, msg="GET %s", args=(self,)):
                resp = session.get(self.geturl(), stream=stream, timeout=self._config.timeout)

            if resp.status_code != requests.codes.ok:  # 200
                raise FileNotFoundError(
                    f"Unable to read resource {self}; status: {resp.status_code} {resp.reason}"
                )
            if not stream:
                return resp.content
            else:
                return next(resp.iter_content(chunk_size=size))

    def write(self, data: bytes, overwrite: bool = True) -> None:
        """Write the supplied bytes to the new resource.

        Parameters
        ----------
        data : `bytes`
            The bytes to write to the resource. The entire contents of the
            resource will be replaced.
        overwrite : `bool`, optional
            If `True` the resource will be overwritten if it exists. Otherwise
            the write will fail.
        """
        log.debug("Writing to remote resource: %s", self.geturl())
        if not overwrite and self.exists():
            raise FileExistsError(f"Remote resource {self} exists and overwrite has been disabled")

        # Ensure the parent directory exists.
        # This is only meaningful and appropriate for WebDAV, not the general
        # HTTP case.  e.g. for S3 HTTP URLs, the underlying service has no
        # concept of 'directories' at all.
        if self.is_webdav_endpoint:
            self.parent().mkdir()

        # Upload the data.
        log.debug("Writing data to remote resource: %s", self.geturl())
        self._put(data=data)

    def transfer_from(
        self,
        src: ResourcePath,
        transfer: str = "copy",
        overwrite: bool = False,
        transaction: TransactionProtocol | None = None,
    ) -> None:
        """Transfer the current resource to a Webdav repository.

        Parameters
        ----------
        src : `ResourcePath`
            Source URI.
        transfer : `str`
            Mode to use for transferring the resource. Supports the following
            options: copy.
        overwrite : `bool`, optional
            Whether overwriting the remote resource is allowed or not.
        transaction : `~lsst.resources.utils.TransactionProtocol`, optional
            Currently unused.
        """
        # Fail early to prevent delays if remote resources are requested.
        if transfer not in self.transferModes:
            raise ValueError(f"Transfer mode {transfer} not supported by URI scheme {self.scheme}")

        # Existence checks cost time so do not call this unless we know
        # that debugging is enabled.
        if log.isEnabledFor(logging.DEBUG):
            log.debug(
                "Transferring %s [exists: %s] -> %s [exists: %s] (transfer=%s)",
                src,
                src.exists(),
                self,
                self.exists(),
                transfer,
            )

        # Short circuit immediately if the URIs are identical.
        if self == src:
            log.debug(
                "Target and destination URIs are identical: %s, returning immediately."
                " No further action required.",
                self,
            )
            return

        if not overwrite and self.exists():
            raise FileExistsError(f"Destination path {self} already exists.")

        if transfer == "auto":
            transfer = self.transferDefault

        # We can use webDAV 'COPY' or 'MOVE' if both the current and source
        # resources are located in the same server.
        if isinstance(src, type(self)) and self.root_uri() == src.root_uri() and self.is_webdav_endpoint:
            log.debug("Transfer from %s to %s directly", src, self)
            return self._move(src) if transfer == "move" else self._copy(src)

        # For resources of different classes or for plain HTTP resources we can
        # perform the copy or move operation by downloading to a local file
        # and uploading to the destination.
        self._copy_via_local(src)

        # This was an explicit move, try to remove the source.
        if transfer == "move":
            src.remove()

    def walk(
        self, file_filter: str | re.Pattern | None = None
    ) -> Iterator[list | tuple[ResourcePath, list[str], list[str]]]:
        """Walk the directory tree returning matching files and directories.

        Parameters
        ----------
        file_filter : `str` or `re.Pattern`, optional
            Regex to filter out files from the list before it is returned.

        Yields
        ------
        dirpath : `ResourcePath`
            Current directory being examined.
        dirnames : `list` of `str`
            Names of subdirectories within dirpath.
        filenames : `list` of `str`
            Names of all the files within dirpath.
        """
        if not self.dirLike:
            raise ValueError("Can not walk a non-directory URI")

        # Walking directories is only available on WebDAV back ends.
        if not self.is_webdav_endpoint:
            raise NotImplementedError(f"Walking directory {self} is not implemented by plain HTTP servers")

        if isinstance(file_filter, str):
            file_filter = re.compile(file_filter)

        resp = self._propfind(depth="1")
        if resp.status_code == requests.codes.multi_status:  # 207
            files: list[str] = []
            dirs: list[str] = []

            for prop in _parse_propfind_response_body(resp.text):
                if prop.is_file:
                    files.append(prop.name)
                elif not prop.href.rstrip("/").endswith(self.path.rstrip("/")):
                    # Only include the names of sub-directories not the name of
                    # the directory being walked.
                    dirs.append(prop.name)

            if file_filter is not None:
                files = [f for f in files if file_filter.search(f)]

            if not dirs and not files:
                return
            else:
                yield type(self)(self, forceAbsolute=False, forceDirectory=True), dirs, files

            for dir in dirs:
                new_uri = self.join(dir, forceDirectory=True)
                yield from new_uri.walk(file_filter)

    def generate_presigned_get_url(self, *, expiration_time_seconds: int) -> str:
        """Return a pre-signed URL that can be used to retrieve this resource
        using an HTTP GET without supplying any access credentials.

        Parameters
        ----------
        expiration_time_seconds : `int`
            Number of seconds until the generated URL is no longer valid.

        Returns
        -------
        url : `str`
            HTTP URL signed for GET.
        """
        if not self.is_webdav_endpoint:
            # This is already an HTTP URL readable without any authentication
            # credentials, so return it as-is.
            return str(self)

        return self._sign_with_macaroon(ActivityCaveat.DOWNLOAD, expiration_time_seconds)

    def generate_presigned_put_url(self, *, expiration_time_seconds: int) -> str:
        """Return a pre-signed URL that can be used to upload a file to this
        path using an HTTP PUT without supplying any access credentials.

        Parameters
        ----------
        expiration_time_seconds : `int`
            Number of seconds until the generated URL is no longer valid.

        Returns
        -------
        url : `str`
            HTTP URL signed for PUT.
        """
        if not self.is_webdav_endpoint:
            return super().generate_presigned_put_url(expiration_time_seconds=expiration_time_seconds)

        return self._sign_with_macaroon(ActivityCaveat.UPLOAD, expiration_time_seconds)

    def to_fsspec(self) -> tuple[AbstractFileSystem, str]:
        """Return an abstract file system and path that can be used by fsspec.

        Returns
        -------
        fs : `fsspec.spec.AbstractFileSystem`
            A file system object suitable for use with the returned path.
        path : `str`
            A path that can be opened by the file system object.
        """
        if (
            fsspec is None
            or not self.is_webdav_endpoint
            or self.server not in HttpResourcePath.SUPPORTED_URL_SIGNERS
        ):
            return super().to_fsspec()

        if self.isdir():
            raise NotImplementedError(
                f"method HttpResourcePath.to_fsspec() not implemented for directory {self}"
            )

        async def get_client_session(**kwargs: Any) -> ClientSession:
            """Return a aiohttp.ClientSession configured to use an
            `aiohttp.TCPConnector` shared by all instances of this class.

            Parameters
            ----------
            **kwargs : `Any`
                Keyword arguments passed unmodified to the contructor of
                `aiohttp.ClientSession`.

            Returns
            -------
            session : `aiohttp.ClientSession`
                Client session that `aiohttp.HTTPFileSystem` will use to pool
                TCP connections to the server.
            """
            if HttpResourcePath._tcp_connector is None:
                HttpResourcePath._tcp_connector = TCPConnector(ssl=self._config.ssl_context)

            return ClientSession(connector=HttpResourcePath._tcp_connector, **kwargs)

        # Retrieve a signed URL for download valid for 1 hour.
        url = self.generate_presigned_get_url(expiration_time_seconds=3_600)

        # HTTPFileSystem constructors accepts the argument 'block_size'. The
        # default value is 'fsspec.utils.DEFAULT_BLOCK_SIZE' which is 5 MB.
        # That seems to be a reasonable block size for downloading files.
        return HTTPFileSystem(get_client=get_client_session), url

    def _sign_with_macaroon(self, activity: ActivityCaveat, expiration_time_seconds: int) -> str:
        # dCache and XRootD webDAV servers support delivery of macaroons.
        #
        # For details about dCache macaroons see:
        #    https://www.dcache.org/manuals/UserGuide-9.2/macaroons.shtml
        if self.server is None:
            raise NotImplementedError(f"server for '{self}' does not support signing URLs")
        elif self.server not in HttpResourcePath.SUPPORTED_URL_SIGNERS:
            raise NotImplementedError(f"server '{self.server}' does not support signing for {self}")

        match activity:
            case ActivityCaveat.DOWNLOAD:
                activity_caveat = "DOWNLOAD,LIST"
            case ActivityCaveat.UPLOAD:
                activity_caveat = "UPLOAD,LIST"

        # Retrieve a macaroon for the requested activities and duration
        headers = {"Content-Type": "application/macaroon-request"}
        body = {
            "caveats": [
                f"activity:{activity_caveat}",
            ],
            "validity": f"PT{expiration_time_seconds}S",
        }
        resp = self._post(data=json.dumps(body), headers=headers)
        if resp.status_code != requests.codes.ok:
            raise ValueError(
                f"could not retrieve a macaroon for URL {self}, status: {resp.status_code} {resp.reason}"
            )

        # We are expecting the body of the response to be formatted in JSON.
        # dCache sets the 'Content-Type' of the response to 'application/json'
        # but XRootD does not set any 'Content-Type' header 8-[
        #
        # An example of a response body returned by dCache is shown below:
        # {
        #    "macaroon": "MDA[...]Qo",
        #    "uri": {
        #      "targetWithMacaroon": "https://dcache.example.org/?authz=MD...",
        #      "baseWithMacaroon": "https://dcache.example.org/?authz=MD...",
        #      "target": "https://dcache.example.org/",
        #      "base": "https://dcache.example.org/"
        #    }
        # }
        #
        # An example of a response body returned by XRootD is shown below:
        # {
        #    "macaroon": "MDA[...]Qo",
        #    "expires_in": 86400
        # }
        try:
            response_body = json.loads(resp.text)
            if "macaroon" in response_body:
                return f"{self}?authz={response_body['macaroon']}"
            else:
                raise ValueError(f"could not retrieve macaroon for URL {self}")
        except json.JSONDecodeError:
            raise ValueError(f"could not deserialize response to POST request for URL {self}")

    def _as_local(self) -> tuple[str, bool]:
        """Download object over HTTP and place in temporary directory.

        Returns
        -------
        path : `str`
            Path to local temporary file.
        temporary : `bool`
            Always returns `True`. This is always a temporary file.
        """
        # Use the session as a context manager to ensure that connections
        # to both the front end and back end servers are closed after the
        # download operation is finished.
        with self.data_session as session:
            resp = session.get(self.geturl(), stream=True, timeout=self._config.timeout)
            if resp.status_code != requests.codes.ok:
                raise FileNotFoundError(
                    f"Unable to download resource {self}; status: {resp.status_code} {resp.reason}"
                )

            tmpdir, buffer_size = self._config.tmpdir_buffersize
            with ResourcePath.temporary_uri(
                suffix=self.getExtension(), prefix=ResourcePath(tmpdir, forceDirectory=True), delete=False
            ) as tmp_uri:
                expected_length = int(resp.headers.get("Content-Length", "-1"))
                with time_this(
                    log,
                    msg="GET %s [length=%d] to local file %s [chunk_size=%d]",
                    args=(self, expected_length, tmp_uri, buffer_size),
                    mem_usage=self._config.collect_memory_usage,
                    mem_unit=u.mebibyte,
                ):
                    content_length = 0
                    with open(tmp_uri.ospath, "wb", buffering=buffer_size) as tmpFile:
                        for chunk in resp.iter_content(chunk_size=buffer_size):
                            tmpFile.write(chunk)
                            content_length += len(chunk)

            # Check that the expected and actual content lengths match. Perform
            # this check only when the contents of the file was not encoded by
            # the server.
            if (
                "Content-Encoding" not in resp.headers
                and expected_length >= 0
                and expected_length != content_length
            ):
                raise ValueError(
                    f"Size of downloaded file does not match value in Content-Length header for {self}: "
                    f"expecting {expected_length} and got {content_length} bytes"
                )

            return tmpFile.name, True

    def _send_webdav_request(
        self,
        method: str,
        url: str | None = None,
        headers: dict[str, str] | None = None,
        body: str | None = None,
        session: requests.Session | None = None,
        timeout: tuple[float, float] | None = None,
    ) -> requests.Response:
        """Send a webDAV request and correctly handle redirects.

        Parameters
        ----------
        method : `str`
            The mthod of the HTTP request to be sent, e.g. PROPFIND, MKCOL.
        headers : `dict`, optional
            A dictionary of key-value pairs (both strings) to include as
            headers in the request.
        body : `str`, optional
            The body of the request.

        Notes
        -----
        This way of sending webDAV requests is necessary for handling
        redirection ourselves, since the 'requests' package changes the method
        of the redirected request when the server responds with status 302 and
        the method of the original request is not HEAD (which is the case for
        webDAV requests).

        That means that when the webDAV server we interact with responds with
        a redirection to a PROPFIND or MKCOL request, the request gets
        converted to a GET request when sent to the redirected location.

        See `requests.sessions.SessionRedirectMixin.rebuild_method()` in
            https://github.com/psf/requests/blob/main/requests/sessions.py

        This behavior of the 'requests' package is meant to be compatible with
        what is specified in RFC 9110:

            https://www.rfc-editor.org/rfc/rfc9110#name-302-found

        For our purposes, we do need to follow the redirection and send a new
        request using the same HTTP verb.
        """
        if url is None:
            url = self.geturl()

        if headers is None:
            headers = {}

        if session is None:
            session = self.metadata_session

        if timeout is None:
            timeout = self._config.timeout

        with time_this(
            log,
            msg="%s %s",
            args=(
                method,
                url,
            ),
            mem_usage=self._config.collect_memory_usage,
            mem_unit=u.mebibyte,
        ):
            for _ in range(max_redirects := 5):
                resp = session.request(
                    method,
                    url,
                    data=body,
                    headers=headers,
                    stream=False,
                    timeout=timeout,
                    allow_redirects=False,
                )
                if resp.is_redirect:
                    url = resp.headers["Location"]
                else:
                    return resp

            # We reached the maximum allowed number of redirects.
            # Stop trying.
            raise ValueError(
                f"Could not get a response to {method} request for {self} after {max_redirects} redirections"
            )

    def _propfind(self, body: str | None = None, depth: str = "0") -> requests.Response:
        """Send a PROPFIND webDAV request and return the response.

        Parameters
        ----------
        body : `str`, optional
            The body of the PROPFIND request to send to the server. If
            provided, it is expected to be a XML document.
        depth : `str`, optional
            The value of the 'Depth' header to include in the request.

        Returns
        -------
        response : `requests.Response`
            Response to the PROPFIND request.

        Notes
        -----
        It raises `ValueError` if the status code of the PROPFIND request
        is different from "207 Multistatus" or "404 Not Found".
        """
        if body is None:
            # Request only the DAV live properties we are explicitly interested
            # in namely 'resourcetype', 'getcontentlength', 'getlastmodified'
            # and 'displayname'.
            body = (
                """<?xml version="1.0" encoding="utf-8" ?>"""
                """<D:propfind xmlns:D="DAV:"><D:prop>"""
                """<D:resourcetype/><D:getcontentlength/><D:getlastmodified/><D:displayname/>"""
                """</D:prop></D:propfind>"""
            )
        headers = {
            "Depth": depth,
            "Content-Type": 'application/xml; charset="utf-8"',
            "Content-Length": str(len(body)),
        }
        resp = self._send_webdav_request("PROPFIND", headers=headers, body=body)
        if resp.status_code in (requests.codes.multi_status, requests.codes.not_found):
            return resp
        else:
            raise ValueError(
                f"Unexpected response for PROPFIND request for {self}, status: {resp.status_code} "
                f"{resp.reason}"
            )

    def _options(self) -> requests.Response:
        """Send a OPTIONS webDAV request for this resource."""
        resp = self._send_webdav_request("OPTIONS")
        if resp.status_code in (requests.codes.ok, requests.codes.created):
            return resp

        raise ValueError(
            f"Unexpected response to OPTIONS request for {self}, status: {resp.status_code} {resp.reason}"
        )

    def _head(self) -> requests.Response:
        """Send a HEAD request for this resource."""
        if not self.is_webdav_endpoint:
            # The remote is a plain HTTP server.
            return self._head_non_webdav_url()
        return self._send_webdav_request("HEAD")

    def _mkcol(self) -> None:
        """Send a MKCOL webDAV request to create a collection. The collection
        may already exist.
        """
        resp = self._send_webdav_request("MKCOL")
        if resp.status_code == requests.codes.created:  # 201
            return

        if resp.status_code == requests.codes.method_not_allowed:  # 405
            # The remote directory already exists
            log.debug("Can not create directory: %s may already exist: skipping.", self.geturl())
        else:
            raise ValueError(f"Can not create directory {self}, status: {resp.status_code} {resp.reason}")

    def _delete(self) -> None:
        """Send a DELETE webDAV request for this resource."""
        log.debug("Deleting %s ...", self.geturl())

        # If this is a directory, ensure the remote is a webDAV server because
        # plain HTTP servers don't support DELETE requests on non-file
        # paths.
        if self.dirLike and not self.is_webdav_endpoint:
            raise NotImplementedError(
                f"Deletion of directory {self} is not implemented by plain HTTP servers"
            )

        # Deleting non-empty directories may take some time, so increase
        # the timeout for getting a response from the server.
        timeout = self._config.timeout
        if self.dirLike:
            timeout = (timeout[0], timeout[1] * 100)
        resp = self._send_webdav_request("DELETE", timeout=timeout)
        if resp.status_code in (
            requests.codes.ok,
            requests.codes.accepted,
            requests.codes.no_content,
            requests.codes.not_found,
        ):
            # We can get a "404 Not Found" error when the file or directory
            # does not exist or when the DELETE request was retried several
            # times and a previous attempt actually deleted the resource.
            # Therefore we consider that a "Not Found" response is not an
            # error since we reached the state desired by the user.
            return
        else:
            # TODO: the response to a DELETE request against a webDAV server
            # may be multistatus. If so, we need to parse the reponse body to
            # determine more precisely the reason of the failure (e.g. a lock)
            # and provide a more helpful error message.
            raise ValueError(f"Unable to delete resource {self}; status: {resp.status_code} {resp.reason}")

    def _copy_via_local(self, src: ResourcePath) -> None:
        """Replace the contents of this resource with the contents of a remote
        resource by using a local temporary file.

        Parameters
        ----------
        src : `HttpResourcePath`
            The source of the contents to copy to `self`.
        """
        with src.as_local() as local_uri:
            log.debug("Transfer from %s to %s via local file %s", src, self, local_uri)
            with open(local_uri.ospath, "rb") as f:
                self._put(data=f)

    def _copy_or_move(self, method: str, src: HttpResourcePath) -> None:
        """Send a COPY or MOVE webDAV request to copy or replace the contents
        of this resource with the contents of another resource located in the
        same server.

        Parameters
        ----------
        method : `str`
            The method to perform. Valid values are "COPY" or "MOVE" (in
            uppercase).
        src : `HttpResourcePath`
            The source of the contents to move to `self`.
        """
        headers = {"Destination": self.geturl()}
        resp = self._send_webdav_request(method, url=src.geturl(), headers=headers, session=self.data_session)
        if resp.status_code in (requests.codes.created, requests.codes.no_content):
            return

        if resp.status_code == requests.codes.multi_status:
            tree = eTree.fromstring(resp.content)
            status_element = tree.find("./{DAV:}response/{DAV:}status")
            status = status_element.text if status_element is not None else "unknown"
            error = tree.find("./{DAV:}response/{DAV:}error")
            raise ValueError(f"{method} returned multistatus reponse with status {status} and error {error}")
        else:
            raise ValueError(
                f"{method} operation from {src} to {self} failed, status: {resp.status_code} {resp.reason}"
            )

    def _copy(self, src: HttpResourcePath) -> None:
        """Send a COPY webDAV request to replace the contents of this resource
        (if any) with the contents of another resource located in the same
        server.

        Parameters
        ----------
        src : `HttpResourcePath`
            The source of the contents to copy to `self`.
        """
        # Neither dCache nor XrootD currently implement the COPY
        # webDAV method as documented in
        #    http://www.webdav.org/specs/rfc4918.html#METHOD_COPY
        # (See issues DM-37603 and DM-37651 for details)
        #
        # For the time being, we use a temporary local file to
        # perform the copy client side.
        # TODO: when those 2 issues above are solved remove the 3 lines below.
        must_use_local = True
        if must_use_local:
            return self._copy_via_local(src)

        return self._copy_or_move("COPY", src)

    def _move(self, src: HttpResourcePath) -> None:
        """Send a MOVE webDAV request to replace the contents of this resource
        with the contents of another resource located in the same server.

        Parameters
        ----------
        src : `HttpResourcePath`
            The source of the contents to move to `self`.
        """
        return self._copy_or_move("MOVE", src)

    def _post(self, data: str | None = None, headers: dict[str, str] | None = None) -> requests.Response:
        """Perform an HTTP POST request and returns the received response.

        Parameters
        ----------
        body : `bytes`
            The contents of the request body.
        """
        resp = self.metadata_session.request(
            "POST",
            self.geturl(),
            data=data,
            headers=headers,
            stream=False,
            timeout=self._config.timeout,
            allow_redirects=True,
        )
        if resp.status_code == requests.codes.ok:
            return resp

        raise ValueError(f"POST request for {self} failed, status: {resp.status_code} {resp.reason}")

    def _put(self, data: BinaryIO | bytes) -> None:
        """Perform an HTTP PUT request and handle redirection.

        Parameters
        ----------
        data : `Union[BinaryIO, bytes]`
            The data to be included in the body of the PUT request.
        """
        # Retrieve the final URL for this upload by sending a PUT request with
        # no content. Follow a single server redirection to retrieve the
        # final URL.
        headers = {"Content-Length": "0"}

        # If we are explicitly configured for or if we know the remote server
        # is dCache, send an "Expect" header to signal the server that this
        # client knows how to handle redirection in PUT requests.
        #
        # The goal is that the contents of the file we want to upload is sent
        # directly to the dCache pool without transiting through the dCache
        # webDAV door. Otherwise, the uploaded data would transit twice over
        # the network: first from this client to the dCache webDAV door and
        # second from webDAV door to the target pool (i.e. the dCache file
        # server which will ultimately store the data we will upload).
        #
        # Systematically uploading data via dCache webDAV door could add
        # unnecessary load to the door which we can avoid by instead uploading
        # directly to the dCache pool.
        #
        # For further details see section "Redirection on upload":
        #
        # https://www.dcache.org/manuals/UserGuide-9.2/webdav.shtml#redirection
        if self._config.send_expect_on_put or self.server == "dcache":
            headers["Expect"] = "100-continue"

        url = self.geturl()

        # Use the session as a context manager to ensure the underlying
        # connections are closed after finishing uploading the data.
        with self.data_session as session:
            # Send an empty PUT request to get redirected to the final
            # destination.
            log.debug("Sending empty PUT request to %s", url)
            with time_this(
                log,
                msg="PUT (no data) %s",
                args=(url,),
                mem_usage=self._config.collect_memory_usage,
                mem_unit=u.mebibyte,
            ):
                resp = session.request(
                    "PUT",
                    url,
                    data=None,
                    headers=headers,
                    stream=False,
                    timeout=self._config.timeout,
                    allow_redirects=False,
                )
                if resp.is_redirect:
                    url = resp.headers["Location"]

            # Upload the data to the final destination.
            log.debug("Uploading data to %s", url)

            # Ask the server to compute and record a checksum of the uploaded
            # file contents, for later integrity checks. Since we don't compute
            # the digest ourselves while uploading the data, we cannot control
            # after the request is complete that the data we uploaded is
            # identical to the data recorded by the server, but at least the
            # server has recorded a digest of the data it stored.
            #
            # See RFC-3230 for details and
            # https://www.iana.org/assignments/http-dig-alg/http-dig-alg.xhtml
            # for the list of supported digest algorithhms.
            # In addition, note that not all servers implement this RFC so
            # the checksum may not be computed by the server.
            put_headers: dict[str, str] | None = None
            if digest := self._config.digest_algorithm:
                put_headers = {"Want-Digest": digest}

            with time_this(
                log,
                msg="PUT %s",
                args=(url,),
                mem_usage=self._config.collect_memory_usage,
                mem_unit=u.mebibyte,
            ):
                resp = session.request(
                    "PUT",
                    url,
                    data=data,
                    headers=put_headers,
                    stream=False,
                    timeout=self._config.timeout,
                    allow_redirects=False,
                )
                if resp.status_code in (
                    requests.codes.ok,
                    requests.codes.created,
                    requests.codes.no_content,
                ):
                    return
                else:
                    raise ValueError(f"Can not write file {self}, status: {resp.status_code} {resp.reason}")

    @contextlib.contextmanager
    def _openImpl(
        self,
        mode: str = "r",
        *,
        encoding: str | None = None,
    ) -> Iterator[ResourceHandleProtocol]:
        resp = self._head()
        accepts_range = resp.status_code == requests.codes.ok and resp.headers.get("Accept-Ranges") == "bytes"
        handle: ResourceHandleProtocol
        if mode in ("rb", "r") and accepts_range:
            handle = HttpReadResourceHandle(mode, log, self, timeout=self._config.timeout)
            if mode == "r":
                # cast because the protocol is compatible, but does not have
                # BytesIO in the inheritance tree
                yield io.TextIOWrapper(cast(Any, handle), encoding=encoding)
            else:
                yield handle
        else:
            with super()._openImpl(mode, encoding=encoding) as http_handle:
                yield http_handle


def _dump_response(resp: requests.Response) -> None:
    """Log the contents of a HTTP or webDAV request and its response.

    Parameters
    ----------
    resp : `requests.Response`
        The response to log.

    Notes
    -----
    Intended for development purposes only.
    """
    log.debug("-----------------------------------------------")
    log.debug("Request")
    log.debug("   method=%s", resp.request.method)
    log.debug("   URL=%s", resp.request.url)
    log.debug("   headers=%s", resp.request.headers)
    if resp.request.method == "PUT":
        log.debug("   body=<data>")
    elif resp.request.body is None:
        log.debug("   body=<empty>")
    else:
        log.debug("   body=%r", resp.request.body[:120])

    log.debug("Response:")
    log.debug("   status_code=%d", resp.status_code)
    log.debug("   headers=%s", resp.headers)
    if not resp.content:
        log.debug("   body=<empty>")
    elif "Content-Type" in resp.headers and resp.headers["Content-Type"] == "text/plain":
        log.debug("   body=%r", resp.content)
    else:
        log.debug("   body=%r", resp.content[:80])


def _is_protected(filepath: str) -> bool:
    """Return true if the permissions of file at filepath only allow for access
    by its owner.

    Parameters
    ----------
    filepath : `str`
        Path of a local file.
    """
    if not os.path.isfile(filepath):
        return False
    mode = stat.S_IMODE(os.stat(filepath).st_mode)
    owner_accessible = bool(mode & stat.S_IRWXU)
    group_accessible = bool(mode & stat.S_IRWXG)
    other_accessible = bool(mode & stat.S_IRWXO)
    return owner_accessible and not group_accessible and not other_accessible


def _parse_propfind_response_body(body: str) -> list[DavProperty]:
    """Parse the XML-encoded contents of the response body to a webDAV PROPFIND
    request.

    Parameters
    ----------
    body : `str`
        XML-encoded response body to a PROPFIND request

    Returns
    -------
    responses : `List[DavProperty]`

    Notes
    -----
    Is is expected that there is at least one reponse in `body`, otherwise
    this function raises.
    """
    # A response body to a PROPFIND request is of the form (indented for
    # readability):
    #
    # <?xml version="1.0" encoding="UTF-8"?>
    # <D:multistatus xmlns:D="DAV:">
    #     <D:response>
    #         <D:href>path/to/resource</D:href>
    #         <D:propstat>
    #             <D:prop>
    #                 <D:resourcetype>
    #                     <D:collection xmlns:D="DAV:"/>
    #                 </D:resourcetype>
    #                 <D:getlastmodified>
    #                     Fri, 27 Jan 2 023 13:59:01 GMT
    #                 </D:getlastmodified>
    #                 <D:getcontentlength>
    #                   12345
    #                 </D:getcontentlength>
    #             </D:prop>
    #             <D:status>
    #                 HTTP/1.1 200 OK
    #             </D:status>
    #         </D:propstat>
    #     </D:response>
    #     <D:response>
    #        ...
    #     </D:response>
    #     <D:response>
    #        ...
    #     </D:response>
    # </D:multistatus>

    # Scan all the 'response' elements and extract the relevant properties
    responses = []
    multistatus = eTree.fromstring(body.strip())
    for response in multistatus.findall("./{DAV:}response"):
        responses.append(DavProperty(response))

    if responses:
        return responses
    else:
        # Could not parse the body
        raise ValueError(f"Unable to parse response for PROPFIND request: {body}")


class DavProperty:
    """Helper class to encapsulate select live DAV properties of a single
    resource, as retrieved via a PROPFIND request.

    Parameters
    ----------
    response : `eTree.Element` or `None`
        The XML response defining the DAV property.
    """

    # Regular expression to compare against the 'status' element of a
    # PROPFIND response's 'propstat' element.
    _status_ok_rex = re.compile(r"^HTTP/.* 200 .*$", re.IGNORECASE)

    def __init__(self, response: eTree.Element | None):
        self._href: str = ""
        self._displayname: str = ""
        self._collection: bool = False
        self._getlastmodified: str = ""
        self._getcontentlength: int = -1

        if response is not None:
            self._parse(response)

    def _parse(self, response: eTree.Element) -> None:
        # Extract 'href'.
        if (element := response.find("./{DAV:}href")) is not None:
            # We need to use "str(element.text)"" instead of "element.text" to
            # keep mypy happy.
            self._href = str(element.text).strip()
        else:
            raise ValueError(
                "Property 'href' expected but not found in PROPFIND response: "
                f"{eTree.tostring(response, encoding='unicode')}"
            )

        for propstat in response.findall("./{DAV:}propstat"):
            # Only extract properties of interest with status OK.
            status = propstat.find("./{DAV:}status")
            if status is None or not self._status_ok_rex.match(str(status.text)):
                continue

            for prop in propstat.findall("./{DAV:}prop"):
                # Parse "collection".
                if (element := prop.find("./{DAV:}resourcetype/{DAV:}collection")) is not None:
                    self._collection = True

                # Parse "getlastmodified".
                if (element := prop.find("./{DAV:}getlastmodified")) is not None:
                    self._getlastmodified = str(element.text)

                # Parse "getcontentlength".
                if (element := prop.find("./{DAV:}getcontentlength")) is not None:
                    self._getcontentlength = int(str(element.text))

                # Parse "displayname".
                if (element := prop.find("./{DAV:}displayname")) is not None:
                    self._displayname = str(element.text)

        # Some webDAV servers don't include the 'displayname' property in the
        # response so try to infer it from the value of the 'href' property.
        # Depending on the server the href value may end with '/'.
        if not self._displayname:
            self._displayname = os.path.basename(self._href.rstrip("/"))

        # Force a size of 0 for collections.
        if self._collection:
            self._getcontentlength = 0

    @property
    def exists(self) -> bool:
        # It is either a directory or a file with length of at least zero
        return self._collection or self._getcontentlength >= 0

    @property
    def is_directory(self) -> bool:
        return self._collection

    @property
    def is_file(self) -> bool:
        return not self._collection

    @property
    def size(self) -> int:
        return self._getcontentlength

    @property
    def name(self) -> str:
        return self._displayname

    @property
    def href(self) -> str:
        return self._href
