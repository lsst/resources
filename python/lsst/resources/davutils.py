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

import base64
import enum
import io
import json
import logging
import os
import posixpath
import random
import re
import stat
import threading
import time
import xml.etree.ElementTree as eTree
from datetime import datetime
from http import HTTPStatus
from typing import Any, BinaryIO

try:
    import fsspec
    from fsspec.spec import AbstractFileSystem
except ImportError:
    fsspec = None
    AbstractFileSystem = type

import yaml
from astropy import units as u
from urllib3 import PoolManager
from urllib3.response import HTTPResponse
from urllib3.util import Retry, Timeout, Url, parse_url

from lsst.utils.timer import time_this

# Use the same logger than `dav.py`.
log = logging.getLogger(f"""{__name__.replace(".davutils", ".dav")}""")


def normalize_path(path: str | None) -> str:
    """Normalize a path intended to be part of a URL.

    A path of the form "///a/b/c///../d/e/" would be normalized as "/a/b/d/e".
    The returned path is always absolute, i.e. starts by "/" and never
    ends by "/" except when the path is exactly "/" and does not contain
    "." nor "..". It does not contain consecutive "/" either.

    Parameters
    ----------
    path : `str`, optional
        Path to normalize, e.g. '/path/to/..///normalize/'

    Returns
    -------
    url : `str`
        Normalized URL, e.g. '/path/normalize'
    """
    return "/" if not path else "/" + posixpath.normpath(path).lstrip("/")


def normalize_url(url: str, preserve_scheme: bool = False, preserve_path: bool = True) -> str:
    """Normalize a URL so that scheme be 'http' or 'https' and the URL path
    is normalized.

    Parameters
    ----------
    url : `str`
        URL to normalize, e.g. 'davs://example.org:1234///path/to//../dir/'

    preserve_scheme : `bool`
        If True the scheme of `url` will be preserved. Otherwise the scheme
        of the returned normalized URL will be 'http' or 'https'.

    preserve_path :  `bool`
        if True, the path of `url` will be preserved in the returned
        normalized URL, otherwise, the returned URL will have '/' as path.

    Returns
    -------
    url : `str`
        Normalized URL, e.g. 'https://example.org:1234/path/dir'
    """
    parsed = parse_url(url)
    if parsed.scheme is None:
        scheme = "http"
    else:
        scheme = parsed.scheme if preserve_scheme else parsed.scheme.replace("dav", "http")
    path = normalize_path(parsed.path) if preserve_path else "/"
    return Url(scheme=scheme, host=parsed.host, port=parsed.port, path=path).url


class DavConfig:
    """Configurable settings a webDAV client must use when interacting with a
    particular storage endpoint.

    Parameters
    ----------
    config : `dict[str, str]`
        Dictionary of configurable settings for the webdav endpoint which
        base URL is `config["base_url"]`.

        For instance, if `config["base_url"]` is

            "davs://webdav.example.org:1234/"

        any object of class `DavResourcePath` like

            "davs://webdav.example.org:1234/path/to/any/file"

        will use the settings in this configuration to configure its client.
    """

    # Timeout in seconds to establish a network connection with the remote
    # server.
    DEFAULT_TIMEOUT_CONNECT: float = 10.0

    # Timeout in seconds to read the response to a request sent to a server.
    # This is total time for reading both the headers and the response body.
    # It must be large enough to allow for upload and download of files
    # of typical size the webdav client supports.
    DEFAULT_TIMEOUT_READ: float = 300.0

    # Maximum number of network connections to persist against each one of
    # the hosts in the frontend and backend server pools.
    # Servers in the frontend pool typically respond to requests such as
    # OPTIONS, PROPFIND, MKCOL, etc.
    #
    # Frontend servers redirect to backend servers to respond to GET and PUT
    # requests (e.g. dCache) but sometimes also for metadata requests such as
    # PROPFIND or HEAD (e.g. XRootD).
    DEFAULT_PERSISTENT_CONNECTIONS_FRONTEND: int = 50
    DEFAULT_PERSISTENT_CONNECTIONS_BACKEND: int = 100

    # Size of the buffer (in mebibytes, i.e. 1024*1024 bytes) the webdav
    # client of this endpoint will use when sending requests and receiving
    # responses.
    DEFAULT_BUFFER_SIZE: int = 5

    # Number of times to retry requests before failing. Retry happens only
    # under certain conditions.
    DEFAULT_RETRIES: int = 3

    # Minimal and maximal retry backoff (in seconds) for the client to compute
    # the wait time before retrying a request.
    # A value in this interval is randomly selected as the backoff factor
    # every time a request is retried.
    DEFAULT_RETRY_BACKOFF_MIN: float = 1.0
    DEFAULT_RETRY_BACKOFF_MAX: float = 3.0

    # Path to a directory or certificate bundle file where the certificates
    # of the trusted certificate authorities can be found.
    # Those certificates will be used by the client of the webdav endpoint
    # to verify the server's host certificate.
    # If None, the certificates trusted by the system are used.
    DEFAULT_TRUSTED_AUTHORITIES: str | None = None

    # Path to the client certificate and associated private key the webdav
    # client must present to the server for authentication purposes.
    # If None, no client certificate is presented.
    DEFAULT_USER_CERT: str | None = None
    DEFAULT_USER_KEY: str | None = None

    # Token the webdav client must sent to the server for authentication
    # purposes. The token may be the value of the token itself or the path
    # to a file where the token can be found.
    DEFAULT_TOKEN: str | None = None

    # Default checksum algorithm to request the server to compute on every
    # file upload. Not al servers support this.
    # See RFC 3230 for details.
    DEFAULT_REQUEST_CHECKSUM: str | None = None

    # If this option is set to True, the webdav client can return objects
    # compliant to the fsspec specification.
    # See: https://filesystem-spec.readthedocs.io
    DEFAULT_ENABLE_FSSPEC: bool = True

    # If this option is set to True, memory usage is computed and reported
    # when executing in debug mode. Computing memory usage is costly, so only
    # set this when debugging.
    DEFAULT_COLLECT_MEMORY_USAGE: bool = False

    # Accepted checksum algorithms. Must be lowercase.
    ACCEPTED_CHECKSUMS: list[str] = ["adler32", "md5", "sha-256", "sha-512"]

    def __init__(self, config: dict | None = None) -> None:
        if config is None:
            config = {}

        if (base_url := config.get("base_url")) is None:
            self._base_url = "_default_"
        else:
            self._base_url = normalize_url(base_url, preserve_path=False)

        self._timeout_connect: float = float(config.get("timeout_connect", DavConfig.DEFAULT_TIMEOUT_CONNECT))
        self._timeout_read: float = float(config.get("timeout_read", DavConfig.DEFAULT_TIMEOUT_READ))
        self._persistent_connections_frontend: int = int(
            config.get(
                "persistent_connections_frontend",
                DavConfig.DEFAULT_PERSISTENT_CONNECTIONS_FRONTEND,
            )
        )
        self._persistent_connections_backend: int = int(
            config.get(
                "persistent_connections_backend",
                DavConfig.DEFAULT_PERSISTENT_CONNECTIONS_BACKEND,
            )
        )
        self._buffer_size: int = 1_048_576 * int(config.get("buffer_size", DavConfig.DEFAULT_BUFFER_SIZE))
        self._retries: int = int(config.get("retries", DavConfig.DEFAULT_RETRIES))
        self._retry_backoff_min: float = float(
            config.get("retry_backoff_min", DavConfig.DEFAULT_RETRY_BACKOFF_MIN)
        )
        self._retry_backoff_max: float = float(
            config.get("retry_backoff_max", DavConfig.DEFAULT_RETRY_BACKOFF_MAX)
        )
        self._trusted_authorities: str | None = expand_vars(
            config.get("trusted_authorities", DavConfig.DEFAULT_TRUSTED_AUTHORITIES)
        )
        self._user_cert: str | None = expand_vars(config.get("user_cert", DavConfig.DEFAULT_USER_CERT))
        self._user_key: str | None = expand_vars(config.get("user_key", DavConfig.DEFAULT_USER_KEY))
        self._token: str | None = expand_vars(config.get("token", DavConfig.DEFAULT_TOKEN))
        self._enable_fsspec: bool = config.get("enable_fsspec", DavConfig.DEFAULT_ENABLE_FSSPEC)
        self._collect_memory_usage: bool = config.get(
            "collect_memory_usage", DavConfig.DEFAULT_COLLECT_MEMORY_USAGE
        )
        self._request_checksum: str | None = config.get(
            "request_checksum", DavConfig.DEFAULT_REQUEST_CHECKSUM
        )
        if self._request_checksum is not None:
            self._request_checksum = self._request_checksum.lower()
            if self._request_checksum not in DavConfig.ACCEPTED_CHECKSUMS:
                raise ValueError(
                    f"""Value for checksum algorithm {self._request_checksum} for storage endpoint """
                    f"""{self._base_url} is not among the accepted values: {DavConfig.ACCEPTED_CHECKSUMS}"""
                )

    @property
    def base_url(self) -> str:
        return self._base_url

    @property
    def timeout_connect(self) -> float:
        return self._timeout_connect

    @property
    def timeout_read(self) -> float:
        return self._timeout_read

    @property
    def persistent_connections_frontend(self) -> int:
        return self._persistent_connections_frontend

    @property
    def persistent_connections_backend(self) -> int:
        return self._persistent_connections_backend

    @property
    def buffer_size(self) -> int:
        return self._buffer_size

    @property
    def retries(self) -> int:
        return self._retries

    @property
    def retry_backoff_min(self) -> float:
        return self._retry_backoff_min

    @property
    def retry_backoff_max(self) -> float:
        return self._retry_backoff_max

    @property
    def trusted_authorities(self) -> str | None:
        return self._trusted_authorities

    @property
    def token(self) -> str | None:
        return self._token

    @property
    def request_checksum(self) -> str | None:
        return self._request_checksum

    @property
    def user_cert(self) -> str | None:
        return self._user_cert

    @property
    def user_key(self) -> str | None:
        # If no user certificate was specified in the configuration,
        # ignore the private key, even if it was provided.
        if self._user_cert is None:
            return None

        # If we have a user certificate but not a private key, assume the
        # private key is included in the same file as the user certificate.
        # That is typically the case when using a X.509 grid proxy as
        # client certificate.
        return self._user_cert if self._user_key is None else self._user_key

    @property
    def enable_fsspec(self) -> bool:
        return self._enable_fsspec

    @property
    def collect_memory_usage(self) -> bool:
        return self._collect_memory_usage


class DavConfigPool:
    """Registry of configurable settings for all known webDAV endpoints.

    Parameters
    ----------
    filenames : `list[str]`
        List of environment variables or file names to load the configuration
        from. The first file found in the list will be read and the
        configuration settings for all webDAV endpoints will be extracted
        from it. Other files will be ignored.

        Each component of `filenames` can be an environment variable or
        the path of a file which itself can include an environment variable,
        e.g. '$HOME/path/to/config.yaml'.

        The configuration file is a YAML file with the structure below:

          - base_url: "davs://webdav1.example.org:1234/"
            persistent_connections_frontend: 10
            persistent_connections_backend: 100
            timeout_connect: 20.0
            timeout_read: 120.0
            retries: 3
            retry_backoff_min: 1.0
            retry_backoff_max: 3.0
            user_cert: "${X509_USER_PROXY}"
            user_key: "${X509_USER_PROXY}"
            token: "/path/to/bearer/token/file"
            trusted_authorities: "/etc/grid-security/certificates"
            buffer_size: 5
            enable_fsspec: false
            request_checksum: "md5"
            collect_memory_usage: false

          - base_url: "davs://webdav2.example.org:1234/"
            persistent_connections_frontend: 5
            ...

        All settings are optional. If no settings are found in the
        configuration file for a particular webDAV endpoint, sensible
        defaults will be used.

        There is only a single instance of this class. This thead-safe
        singleton is intended to be initialized when the module is imported
        the first time.
    """

    _instance = None
    _lock = threading.Lock()

    def __new__(cls, filename: str | None = None) -> DavConfigPool:
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)

        return cls._instance

    def __init__(self, filename: str | None = None) -> None:
        # Create a default configuration. This configuration is
        # used when a URL doest not match any of the endpoints in the
        # configuration.
        self._default_config: DavConfig = DavConfig()

        # The key of this dictionary is the URL of the webDAV endpoint,
        # e.g. "davs://host.example.org:1234/"
        self._configs: dict[str, DavConfig] = {}

        # Load the configuration from the file we have been provided with,
        # if any.
        if filename is None:
            return

        # filename can be the name of an environment variable or a path.
        # A path can include environment variables
        # (e.g. "$HOME/path/to/config.yaml") or "~"
        # (e.g. "~/path/to/config.yaml")
        if (filename := os.getenv(filename)) is not None:
            # Expand environment variables and '~' in the file name, if any.
            filename = os.path.expandvars(filename)
            filename = os.path.expanduser(filename)
            with open(filename) as file:
                for config_item in yaml.safe_load(file):
                    config = DavConfig(config_item)
                    if config.base_url not in self._configs:
                        self._configs[config.base_url] = config
                    else:
                        # We already have a configuration for the same
                        # endpoint. That is likely a human error in
                        # the configuration file.
                        raise ValueError(
                            f"""configuration file {filename} contains two configurations for """
                            f"""endpoint {config.base_url}"""
                        )

    def get_config_for_url(self, url: str) -> DavConfig:
        """Return the configuration to use a webDAV client when interacting
        whith the server which hosts the resource at `url`.
        """
        # Select the configuration for the endpoint of the provided URL.
        normalized_url: str = normalize_url(url, preserve_path=False)
        if (config := self._configs.get(normalized_url)) is not None:
            return config

        # No config was found for the specified URL. Use the default.
        return self._default_config

    def _destroy(self) -> None:
        """Destroy this class singleton instance.

        Helper method to be used in tests to reset global configuration.
        """
        with DavConfigPool._lock:
            DavConfigPool._instance = None


def make_retry(config: DavConfig) -> Retry:
    """Create a ``urllib3.util.Retry`` object from settings in `config`.

    Parameters
    ----------
    config : `DavConfig`
        Configurable settings for a webDAV storage endpoint.

    Returns
    -------
    retry : `urllib3.util.Retry`
        retry object to he used when creating a ``urllib3.PoolManager``
    """
    backoff_min: float = config.retry_backoff_min
    backoff_max: float = config.retry_backoff_max
    retry = Retry(
        # Total number of retries to allow. Takes precedence over other
        # counts.
        total=2 * config.retries,
        # How many connection-related errors to retry on.
        connect=config.retries,
        # How many times to retry on read errors.
        read=config.retries,
        # Backoff factor to apply between attempts after the second try
        # (seconds). Compute a random jitter to prevent all the clients which
        # started at the same time (even on different hosts) to overwhelm the
        # server by sending requests at the same time.
        backoff_factor=backoff_min + (backoff_max - backoff_min) * random.random(),
        # How many times to retry on bad status codes.
        status=config.retries,
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
                HTTPStatus.TOO_MANY_REQUESTS,  # 429
                HTTPStatus.INTERNAL_SERVER_ERROR,  # 500
                HTTPStatus.BAD_GATEWAY,  # 502
                HTTPStatus.SERVICE_UNAVAILABLE,  # 503
                HTTPStatus.GATEWAY_TIMEOUT,  # 504
            ]
        ),
        # Whether to respect "Retry-After" header on status codes defined
        # above.
        respect_retry_after_header=True,
    )
    return retry


class DavClientPool:
    """Container of reusable webDAV clients, each one specifically configured
    to talk to a single storage endpoint.

    Parameters
    ----------
    config_pool : `DavConfigPool`
        Pool of all known webDAV client configurations.

    Notes
    -----
    There is a single instance of this class. This thead-safe singleton is
    intended to be initialized when the module is imported the first time.
    """

    _instance = None
    _lock = threading.Lock()

    def __new__(cls, config_pool: DavConfigPool) -> DavClientPool:
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)

        return cls._instance

    def __init__(self, config_pool: DavConfigPool) -> None:
        self._config_pool: DavConfigPool = config_pool

        # The key of this dictionnary is a path-stripped URL of the form
        # "davs://host.example.org:1234/". The value is a reusable
        # DavClient to interact with that endpoint.
        self._clients: dict[str, DavClient] = {}

    def get_client_for_url(self, url: str) -> DavClient:
        """Return a client for interacting with the endpoint where `url`
        is hosted.

        The returned client is thread-safe. If a client for that endpoint
        already exists it is reused, otherwise a new client is created
        with the appropriate configuration for interacting with the storage
        endpoint.
        """
        # If we already have a client for this endpoint reuse it.
        url = normalize_url(url, preserve_path=False)
        if (client := self._clients.get(url)) is not None:
            return client

        # No client for this endpoint was found. Create a new one and save it
        # for serving subsequent requests.
        with DavClientPool._lock:
            # If another client was created in the meantime by another thread
            # reuse it.
            if (client := self._clients.get(url)) is not None:
                return client

            config: DavConfig = self._config_pool.get_config_for_url(url)
            self._clients[url] = self._make_client(url, config)

        return self._clients[url]

    def _make_client(self, url: str, config: DavConfig) -> DavClient:
        """Make a webDAV client for interacting with the server at `url`."""
        # Check the server implements webDAV protocol and retrieve its
        # identity so that we can build a client for that specific
        # server implementation.
        client = DavClient(url, config)
        server_details = client.get_server_details(url)
        server_id = server_details.get("Server", None)
        accepts_ranges: bool | str | None = server_details.get("Accept-Ranges", None)
        if accepts_ranges is not None:
            accepts_ranges = accepts_ranges == "bytes"

        if server_id is None:
            # Create a generic webDAV client
            return DavClient(url, config, accepts_ranges)

        if server_id.startswith("dCache/"):
            # Create a client for a dCache webDAV server
            return DavClientDCache(url, config, accepts_ranges)
        elif server_id.startswith("XrootD/"):
            # Create a client for a XrootD webDAV server
            return DavClientXrootD(url, config, accepts_ranges)
        else:
            # Return a generic webDAV client
            return DavClient(url, config, accepts_ranges)

    def _destroy(self) -> None:
        """Destroy this class singleton instance.

        Helper method to be used in tests to reset global configuration.
        """
        with DavClientPool._lock:
            DavClientPool._instance = None


class DavClient:
    """WebDAV client, configured to talk to a single storage endpoint.

    Instances of this class are thread-safe.

    Parameters
    ----------
    url : `str`
        Root URL of the storage endpoint (e.g. "https://host.example.org:1234/")

    config : `DavConfig`
        Configuration to initialize this client.
    """

    def __init__(self, url: str, config: DavConfig, accepts_ranges: bool | None = None) -> None:
        # Lock to protect this client fields from concurrent modification.
        self._lock = threading.Lock()

        # Configuration for the storage endpoint.
        self._config: DavConfig = config

        # Prepare the trusted authorities certificates
        ca_certs, ca_cert_dir = None, None
        if self._config.trusted_authorities is not None:
            if os.path.isdir(self._config.trusted_authorities):
                ca_cert_dir = self._config.trusted_authorities
            elif os.path.isfile(self._config.trusted_authorities):
                ca_certs = self._config.trusted_authorities
            else:
                raise FileNotFoundError(
                    f"Trusted authorities file or directory {self._config.trusted_authorities} does not exist"
                )

        # If a token was specified for this endpoint, prefer it as the
        # authentication method, instead of a <user certificate, private key>
        # pair, even if they were also specified.
        self._authorizer: TokenAuthorizer | None = None
        if self._config.token is not None:
            self._authorizer = TokenAuthorizer(self._config.token)
            user_cert, user_key = None, None
        else:
            user_cert = self._config.user_cert
            user_key = self._config.user_key

        # We use this pool manager for sending requests that the front
        # server typically responds to directly without redirecting (e.g.
        # OPTIONS, HEAD, etc.)
        #
        # Connections in this pool are generally left open by the client but
        # the front-end server may choose to close them in some specific
        # situations (e.g. PUT request with "Expect: 100-continue" header).
        self._frontend = PoolManager(
            # Number of connection pools to cache before discarding the least
            # recently used pool. Each connection pool manages network
            # connections to a single host, so this is basically the number
            # of "host:port" we persist network connections to.
            num_pools=10,
            # Number of connections to the same "host:port" to persist for
            # later reuse. More than 1 is useful in multithreaded situations.
            # If more than this number of network connections are needed at
            # a particular moment, they will be created and used but not
            # perrsisted.
            maxsize=self._config.persistent_connections_frontend,
            # Retry configuration to use by default with requests sent to
            # host in the front end.
            retries=make_retry(self._config),
            # Socket timeout in seconds for each individual connection.
            timeout=Timeout(
                connect=self._config.timeout_connect,
                read=self._config.timeout_read,
            ),
            # Size in bytes of the buffer for reading/writing data from/to
            # the underlying socket.
            blocksize=self._config.buffer_size,
            # Client certificate and private key for esablishing TLS
            # connections. If None, no client certificate is sent to the
            # server. Only relevant for endpoints using secure HTTP protocol.
            cert_file=user_cert,
            key_file=user_key,
            # We require verification of the server certificate.
            cert_reqs="CERT_REQUIRED",
            # Directory where the certificates of the trusted certificate
            # authorities can be found. The contents of that directory
            # must be as expected by OpenSSL.
            ca_cert_dir=ca_cert_dir,
            # Path to a file of concatenated CA certificates in PEM format.
            ca_certs=ca_certs,
        )

        # We use this pool manager to send requests to the backend hosts.
        # Those requests are typically 'GET' and 'PUT'. The backend servers
        # typically leave the connection open after serving the request,
        # but we want the client to have the possibility to close them
        # when there is no benefit of persist those connections.
        #
        # That is the case, for instance, when the backend servers use a
        # range of ports for listening for new connections. In that case
        # it is likely that a connection to the same pair
        #    <backend server, port number>
        # is not going to be reused in a short interval of time
        self._backend = PoolManager(
            num_pools=100,
            maxsize=self._config.persistent_connections_backend,
            retries=make_retry(self._config),
            timeout=Timeout(
                connect=self._config.timeout_connect,
                read=self._config.timeout_read,
            ),
            blocksize=self._config.buffer_size,
            cert_file=user_cert,
            key_file=user_key,
            cert_reqs="CERT_REQUIRED",
            ca_cert_dir=ca_cert_dir,
            ca_certs=ca_certs,
        )

        # Parser of PROPFIND responses.
        self._propfind_parser: DavPropfindParser = DavPropfindParser()

        # Does the remote server accept "Range" header in GET requests?
        # This field is lazy initialized.
        self._accepts_ranges: bool | None = accepts_ranges

        # Base URL of the server this is a client for. It is of the form:
        #   "davs://host.example.org:1234./"
        self._base_url: str = url

    def get_server_details(self, url: str) -> dict[str, str]:
        """
        Retrieve the details of the server and check it  advertises compliance
        to class 1 of webDAV protocol.

        Returns
        -------
        details: `dic[str, str]`
            The keys of the returned dictionary can be "Server" and
            "Accept-Ranges". Any of those keys may not exist in the returned
            dictionary if the server did not include it in its response.

            The values are the values of the corresponding
            headers found in the response to the OPTIONS request.
            Examples of values for the "Server" header are 'dCache/9.2.4' or
            'XrootD/v5.7.1'.
        """
        # Check that the value "1" is part of the value of the "DAV" header in
        # the response to an 'OPTIONS' request.
        #
        # We don't rely on webDAV locks, so a server complying to class 1 is
        # enough for our purposes. All webDAV servers must advertise at least
        # compliance class "1".
        #
        # Compliance classes are documented in
        #    http://www.webdav.org/specs/rfc4918.html#dav.compliance.classes
        #
        # Examples of values for header DAV are:
        #   DAV: 1, 2
        #   DAV: 1, <http://apache.org/dav/propset/fs/1>
        resp = self._options(url)
        if "DAV" not in resp.headers:
            raise ValueError(f"Server of {resp.geturl()} does not implement webDAV protocol")

        if "1" not in resp.headers.get("DAV").replace(" ", "").split(","):
            raise ValueError(
                f"Server of {resp.geturl()} does not advertise required compliance to webDAV protocol class 1"
            )

        # The value of 'Server' header is expected to be of the form
        # 'dCache/9.2.4' or 'XrootD/v5.7.1'. Not all servers include such a
        # header in their response to an OPTIONS request. If no such a
        # header is found in the response, use "_unknown_".
        details: dict[str, str] = {}
        for header in ("Server", "Accept-Ranges"):
            value = resp.headers.get(header, None)
            if value is not None:
                details[header] = value

        return details

    def _options(self, url: str) -> HTTPResponse:
        """Send a HTTP OPTIONS request and return the response.

        Parameters
        ----------
        url : `str`
            Target URL.
        """
        resp = self._request("OPTIONS", url)
        if resp.status in (HTTPStatus.OK, HTTPStatus.CREATED):
            return resp
        else:
            raise ValueError(
                f"""Unexpected response to OPTIONS request to {resp.geturl()}: status {resp.status} """
                f"""{resp.reason}"""
            )

    def _request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        body: BinaryIO | bytes | str | None = None,
        pool_manager: PoolManager | None = None,
        preload_content: bool = True,
        redirect: bool = True,
    ) -> HTTPResponse:
        """Send a generic HTTP request and return the response.

        Parameters
        ----------
        method : `str`
            Request method, e.g. 'GET', 'PUT', 'PROPFIND'.
        url : `str`
            Target URL.
        headers : `dict[str, str]`, optional
            Headers to sent with the request.
        body: `bytes` or `str` or `None`, optional
            Request body.
        pool_manager: `PoolManager`, optional
            Pool manager to use to send the request. By default, the requests
            are sent to the frontend servers.
        preload_content: `bool`, optional
            If True, the response body is downloaded and can be retrieved
            via the returned response `.data` property. If False, the
            caller needs to call `.read()` on the returned response object to
            download the body, either entirely in one call or by chunks.
        redirect: `bool`, optional
            If True, automatically handle redirects. If False, the returned
            response may contain a redirection to another location.

        Returns
        -------
        resp: `HTTPResponse`
            Response to the request as received from the server.
        """
        # If this client is configured to use a bearer token for
        # authentication, ensure we only set the token to requests over secure
        # HTTP to avoid leaking the token.
        headers = {} if headers is None else dict(headers)
        if self._authorizer is not None and url.startswith("https://"):
            self._authorizer.set_authorization(headers)

        # By default, send the request to a frontend server.
        if pool_manager is None:
            pool_manager = self._frontend

        log.debug("sending request %s %s", method, url)

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
            resp = pool_manager.request(
                method,
                url,
                body=body,
                headers=headers,
                preload_content=preload_content,
                redirect=redirect,
            )

        return resp

    def _get(
        self, url: str, headers: dict[str, str] | None = None, preload_content: bool = True
    ) -> HTTPResponse:
        """Send a HTTP GET request.

        Parameters
        ----------
        url : `str`
            Target URL.
        headers : `dict[str, str]`, optional
            Headers to sent with the request.
        preload_content: `bool`, optional
            If True, the response body is downloaded and can be retrieved
            via the returned response `.data` property. If False, the
            caller needs to call the `.read()` on the returned response
            object to download the body.

        Returns
        -------
        resp: `HTTPResponse`
            Response to the GET request as received from the server.
        """
        # Send the GET request to the frontend servers. We handle redirections
        # ourselves.
        headers = {} if headers is None else dict(headers)
        resp = self._request("GET", url, headers=headers, preload_content=preload_content, redirect=False)
        if resp.status in (HTTPStatus.OK, HTTPStatus.PARTIAL_CONTENT):
            return resp

        if resp.status == HTTPStatus.NOT_FOUND:
            raise FileNotFoundError(f"No file found at {resp.geturl()}")

        redirect_location = resp.get_redirect_location()
        if redirect_location is None or redirect_location is False:
            raise ValueError(
                f"Unexpected error in HTTP GET {resp.geturl()}: status {resp.status} {resp.reason}"
            )

        # We were redirected to a backend server so follow the redirection.
        # The response body will be automatically downloaded when
        # `preload_content` is true and the underlying network connection
        # may be kept open for future reuse if the maximum number of
        # connections for the backend pool is not reached.
        url = redirect_location
        resp = self._request(
            "GET",
            url,
            headers=headers,
            pool_manager=self._backend,
            preload_content=preload_content,
        )
        if resp.status not in (HTTPStatus.OK, HTTPStatus.PARTIAL_CONTENT):
            raise ValueError(
                f"Unexpected error in HTTP GET {resp.geturl()}: status {resp.status} {resp.reason}"
            )

        # The caller will access the `resp.data` property or use
        # the `resp.read()` method to read the contents of the
        # response body. If `preload_content` argument is True, the
        # response body is already downloaded, otherwise `resp.read()`
        # will download it.
        return resp

    def _put(
        self,
        url: str,
        data: BinaryIO | bytes,
    ) -> None:
        """Send a HTTP PUT request.

        Parameters
        ----------
        url : `str`
            Target URL.
        data: `BinaryIO` or `bytes`
            Request body.
        """
        # Send a PUT request with empty body and handle redirection. This
        # is useful if the server redirects us; since we cannot rewind the
        # data we are uploading, we don't start uploading data until we
        # connect to the server that will actually serve our request.
        headers = {"Content-Length": "0"}
        resp = self._request("PUT", url, headers=headers, redirect=False)
        if redirect_location := resp.get_redirect_location():
            url = redirect_location
        elif resp.status not in (
            HTTPStatus.OK,
            HTTPStatus.CREATED,
            HTTPStatus.NO_CONTENT,
        ):
            raise ValueError(
                f"""Unexpected response to HTTP request PUT {resp.geturl()}: status {resp.status} """
                f"""{resp.reason} [{resp.data.decode("utf-8")}]"""
            )

        # We may have been redirectred. Upload the file contents to
        # its final destination.

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
        #
        # In addition, note that not all servers implement this RFC so
        # the checksum reqquest may be ignored by the server.
        headers = {}
        if (checksum := self._config.request_checksum) is not None:
            headers = {"Want-Digest": checksum}

        resp = self._request(
            "PUT",
            url,
            body=data,
            headers=headers,
            pool_manager=self._backend,
        )

        if resp.status not in (
            HTTPStatus.OK,
            HTTPStatus.CREATED,
            HTTPStatus.NO_CONTENT,
        ):
            raise ValueError(
                f"""Unexpected response to HTTP request PUT {resp.geturl()}: status {resp.status} """
                f"""{resp.reason} [{resp.data.decode("utf-8")}]"""
            )

    def _head(self, url: str, headers: dict[str, str] | None = None) -> HTTPResponse:
        """Send a HTTP HEAD request and return the response.

        Parameters
        ----------
        url : `str`
            Target URL.

        raise_if_not_found: `bool``
            If the target URL is not found, raise an exception. Otherwise
            just return the response.
        """
        headers = {} if headers is None else dict(headers)
        resp = self._request("HEAD", url, headers=headers)
        match resp.status:
            case HTTPStatus.OK:
                return resp
            case HTTPStatus.NOT_FOUND:
                raise FileNotFoundError(f"No file found at {resp.geturl()}")
            case _:
                raise ValueError(
                    f"""Unexpected response to HEAD request to {resp.geturl()}: status {resp.status} """
                    f"""{resp.reason}"""
                )

    def _propfind(self, url: str, body: str | None = None, depth: str = "0") -> HTTPResponse:
        """Send a HTTP PROPFIND request and return the response.

        Parameters
        ----------
        url : `str`
            Target URL.
        body : `str`, optional
            Request body.
        """
        if body is None:
            # Request only the DAV live properties we are explicitly interested
            # in namely 'resourcetype', 'getcontentlength', 'getlastmodified'
            # and 'displayname'.
            body = (
                """<?xml version="1.0" encoding="utf-8"?>"""
                """<D:propfind xmlns:D="DAV:"><D:prop>"""
                """<D:resourcetype/><D:getcontentlength/><D:getlastmodified/><D:displayname/>"""
                """</D:prop></D:propfind>"""
            )

        headers = {
            "Depth": depth,
            "Content-Type": 'application/xml; charset="utf-8"',
            "Content-Length": str(len(body)),
        }
        resp = self._request("PROPFIND", url=url, headers=headers, body=body)
        if resp.status in (HTTPStatus.MULTI_STATUS, HTTPStatus.NOT_FOUND):
            return resp
        else:
            raise ValueError(
                f"Unexpected response to PROPFIND {resp.geturl()}: status {resp.status} {resp.reason}"
            )

    def stat(self, url: str) -> DavFileMetadata:
        """Return the properties of file or directory located at `url`.

        Parameters
        ----------
        url : `str`
            Target URL.

        Returns
        -------
        result: `DavResourceMetadata``
           Details of the resources at `url`. If no resource was found at
           that URL no exception is raised. Instead the returned details allow
           for detecting that the resource does not exist.
        """
        resp = self._propfind(url)
        match resp.status:
            case HTTPStatus.NOT_FOUND:
                href = url.replace(self._base_url, "", 1)
                return DavFileMetadata(base_url=self._base_url, href=href)
            case HTTPStatus.MULTI_STATUS:
                property = self._propfind_parser.parse(resp.data)[0]
                return DavFileMetadata.from_property(base_url=self._base_url, property=property)
            case _:
                raise ValueError(
                    f"""Unexpected response to HTTP PROPFIND request to {resp.geturl()}: status """
                    f"""{resp.status} {resp.reason}"""
                )

    def info(self, url: str, name: str | None = None) -> dict[str, Any]:
        """Return the details about the file or directory at `url`.

        Parameters
        ----------
        url : `str`
            Target URL.
        name : `str`
            Name of the object to be included in the returned value. If None,
            the `url` is used as name.

        Returns
        -------
        result: `dict``

            For an existing file, the returned value has the form:

            {
               "name": name,
               "size": 1234,
               "type": "file",
               "last_modified":
                    datetime.datetime(2025, 4, 10, 15, 12, 51, 227854),
               "checksums": {
                  "adler32": "0fc5f83f",
                  "md5": "1f57339acdec099c6c0a41f8e3d5fcd0",
               }
            }

            For an existing directory, the returned value has the form:

            {
                "name": name,
                "size": 0,
                "type": "directory",
                "last_modified":
                    datetime.datetime(2025, 4, 10, 15, 12, 51, 227854),
                "checksums": {},
            }

            For an inexisting file or directory, the returned value has the
            form:

            {
                "name": name,
                "size": None,
                "type": None,
                "last_modified":
                    datetime.datetime(1, 1, 1, 0, 0),
                "checksums": {},
            }

        Notes
        -----
        The format of the returned directory is inspired and compatible with
        `fsspec`.

        The size of existing directories is always zero. The `checksums``
        dictionary may be empty if the storage endpoint does not compute
        and store the checksum of the files it stores.
        """
        result: dict[str, Any] = {
            "name": name if name is not None else url,
            "type": None,
            "size": None,
            "last_modified": datetime.min,
            "checksums": {},
        }
        metadata = self.stat(url)
        if not metadata.exists:
            return result

        if metadata.is_dir:
            result.update({"type": "directory", "size": 0})
        else:
            result.update({"type": "file", "size": metadata.size, "checksums": metadata.checksums})

        result.update({"last_modified": metadata.last_modified})
        return result

    def read_dir(self, url: str) -> list[DavFileMetadata]:
        """Return the properties of the files or directories contained in
        directory located at `url`.

        If `url` designates a file, only the details of itself are returned.

        Parameters
        ----------
        url : `str`
            Target URL.

        Returns
        -------
        result: `list[DavResourceMetadata]`
            List of details of each file or directory within `url`.
        """
        resp = self._propfind(url, depth="1")
        if resp.status == HTTPStatus.NOT_FOUND:
            raise FileNotFoundError(f"No directory found at {resp.geturl()}")
        elif resp.status != HTTPStatus.MULTI_STATUS:
            raise ValueError(
                f"""Unexpected response to HTTP PROPFIND request to {resp.geturl()}: status {resp.status} """
                f"""{resp.reason}"""
            )

        if (path := parse_url(url).path) is not None:
            this_dir_href = path.rstrip("/") + "/"
        else:
            this_dir_href = "/"

        result = []
        for property in self._propfind_parser.parse(resp.data):
            # Don't include in the results the metadata of the directory we
            # traversing.
            # Some webDAV servers do not append a "/" to the href of a
            # directory in their response to PROPFIND, so we must take into
            # account that.
            if property.is_file:
                result.append(DavFileMetadata.from_property(base_url=self._base_url, property=property))
            elif property.is_dir and property.href != this_dir_href:
                result.append(DavFileMetadata.from_property(base_url=self._base_url, property=property))

        return result

    def read(self, url: str) -> bytes:
        """Download the contents of file located at `url`.

        Parameters
        ----------
        url : `str`
            Target URL.

        Returns
        -------
        read: `bytes`
            Contents of the file.

        Notes
        -----
        The caller must ensure that the resource at `url` is a file, not
        a directory.
        """
        return self._get(url).data

    def read_range(
        self, url: str, start: int, end: int | None, headers: dict[str, str] | None = None
    ) -> bytes:
        """Download partial content of file located at `url`.

        Parameters
        ----------
        url : `str`
            Target URL.

        start: `int`
            Starting byte offset of the range to download.
        end: `int`
            Ending byte offset of the range to download.
        headers: `dict[str,str]`, optional
            Specific headers to sent with the GET request.

        Returns
        -------
        read: `bytes`
            Partial contents of the file.

        Notes
        -----
        The caller must ensure that the resource at `url` is a file, not
        a directory. This is important because some webDAV servers respond
        with an HTML document when asked for reading a directory.
        """
        headers = {} if headers is None else dict(headers)
        if end is None:
            headers.update({"Range": f"bytes={start}-"})
        else:
            headers.update({"Range": f"bytes={start}-{end}"})

        return self._get(url, headers=headers).data

    def download(self, url: str, filename: str, chunk_size: int, close_connection: bool = False) -> int:
        """Download the content of a file and write it to local file.

        Parameters
        ----------
        url : `str`
            Target URL.

        filename: `str`
            Local file to write the content to. If the file already exists,
            it will be rewritten.

        chunk_size: `int`
            Size of the chunks to write to `filename`.

        Returns
        -------
        count: `int`
            Number of bytes written to `filename`.

        Notes
        -----
        The caller must ensure that the resource at `url` is a file, not
        a directory.
        """
        try:
            resp = self._get(url, preload_content=False)

            # If we were asked to close the connection to the server, disable
            # auto close so that we can explicitly close the connection.
            # By default, urrlib3 releases the connection and keeps it open
            # for later reuse when it consumes the response body.
            if close_connection:
                resp.auto_close = False

            content_length = 0
            with open(filename, "wb", buffering=chunk_size) as file:
                for chunk in resp.stream(chunk_size):
                    file.write(chunk)
                    content_length += len(chunk)

            # Check that the expected and actual content lengths match. Perform
            # this check only when the content of the file was not encoded by
            # the server.
            expected_length: int = int(resp.headers.get("Content-Length", -1))
            if (
                "Content-Encoding" not in resp.headers
                and expected_length != -1
                and expected_length != content_length
            ):
                raise ValueError(
                    f"Size of downloaded file does not match value in Content-Length header for {self}: "
                    f"expecting {expected_length} and got {content_length} bytes"
                )

            return content_length
        finally:
            # Close this connection
            if close_connection:
                resp.close()

    def write(self, url: str, data: BinaryIO | bytes) -> None:
        """Create or rewrite a remote file at `url` with `data` as its
        contents.

        Parameters
        ----------
        url : `str`
            Target URL.

        data: `bytes`
            Sequence of bytes to upload.

        Notes
        -----
        If a file already exists at `url` it will be rewritten.
        """
        self._put(url, data)

    def checksums(self, url: str) -> dict[str, str]:
        """Return the checksums of the contents of file located at `url`.

        The checksums are retrieved from the storage endpoint. There may be
        none if the storage endpoint does not automatically expose the
        checksums it computes.

        Parameters
        ----------
        url : `str`
            Target URL

        Returns
        -------
        checksums: `dict[str, str]`
            A file exists at `url`.
            The key of the dictionary is the lowercased name of the checksum
            algorithm (e.g. "md5", "adler32"). The value is the lowercased
            checksum itself (e.g. "78441cec2479ec8b545c4d6699f542da").
        """
        stat = self.stat(url)
        if not stat.exists:
            raise FileNotFoundError(f"No file found at {url}")

        return stat.checksums if stat.is_file else {}

    def mkcol(self, url: str) -> None:
        """Create a directory at `url`.

        If a directory already exists at `url` no error is returned nor
        exception is raised. An exception is raised if a file exists at `url`.

        Parameters
        ----------
        url : `str`
            Target URL.
        """
        resp = self._request("MKCOL", url)
        if resp.status not in (HTTPStatus.CREATED, HTTPStatus.METHOD_NOT_ALLOWED):
            raise ValueError(f"Can not create directory {resp.geturl()}: status {resp.status} {resp.reason}")

    def delete(self, url: str) -> None:
        """Delete the file or directory at `url`.

        If there is no file or directory at `url` is not considered an error.

        Parameters
        ----------
        url : `str`
            Target URL.

        Notes
        -----
        If `url` designates a directory, some webDAV servers recursively
        remove the directory and its contents. Others, only remove the
        directory if it is empty.

        For a consisten behavior, the caller must check what kind of object
        the target URL is and walk the hierarchy removing all objects.
        """
        resp = self._request("DELETE", url)
        if resp.status not in (
            HTTPStatus.OK,
            HTTPStatus.ACCEPTED,
            HTTPStatus.NO_CONTENT,
            HTTPStatus.NOT_FOUND,
        ):
            raise ValueError(f"Unable to delete resource {resp.geturl()}: status {resp.status} {resp.reason}")

    def accepts_ranges(self, url: str) -> bool:
        """Return `True` if the server supports a 'Range' header in
        GET requests against `url`.
        """
        # If we have already determined that the server accepts "Range" for
        # another URL, we assume that it implements that feature for any
        # file it serves, so reuse that information.
        if self._accepts_ranges is not None:
            return self._accepts_ranges

        with self._lock:
            if self._accepts_ranges is None:
                self._accepts_ranges = self._head(url).headers.get("Accept-Ranges", "") == "bytes"

        return self._accepts_ranges

    def copy(self, source_url: str, destination_url: str, overwrite: bool = False) -> None:
        """Copy the file at `source_url` to `destination_url` in the same
        storage endpoint.

        Parameters
        ----------
        source_url : `str`
            URL of the source file.
        destination_url : `str`
            URL of the destination file. Its parent directory must exist.
        overwrite : `bool`
            If True and a file exists at `destination_url` it will be
            overwritten. Otherwise an exception is raised.
        """
        # Check the source is a file
        if self.stat(source_url).is_dir:
            raise NotImplementedError(f"copy is not implemented for directory {source_url}")

        # Send a COPY request for this file.
        headers = {
            "Destination": destination_url,
            "Overwrite": "T" if overwrite else "F",
        }
        resp = self._request("COPY", source_url, headers=headers)
        if resp.status not in (HTTPStatus.CREATED, HTTPStatus.NO_CONTENT):
            raise ValueError(
                f"Could not copy {resp.geturl()} to {destination_url}: status {resp.status} {resp.reason}"
            )
        return

    def move(self, source_url: str, destination_url: str, overwrite: bool = False) -> None:
        """Move the file at `source_url` to `destination_url` in the same
        storage endpoint.

        Parameters
        ----------
        source_url : `str`
            URL of the source file.
        destination_url : `str`
            URL of the destination file. Its parent directory must exist.
        overwrite : `bool`
            If True and a file exists at `destination_url` it will be
            overwritten. Otherwise an exception is raised.
        """
        headers = {
            "Destination": destination_url,
            "Overwrite": "T" if overwrite else "F",
        }
        resp = self._request("MOVE", source_url, headers=headers)
        if resp.status not in (HTTPStatus.CREATED, HTTPStatus.NO_CONTENT):
            raise ValueError(
                f"""Could not move file {resp.geturl()} to {destination_url}: status {resp.status} """
                f"""{resp.reason}"""
            )

    def generate_presigned_get_url(self, url: str, expiration_time_seconds: int) -> str:
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
        raise NotImplementedError(f"URL signing is not supported by server for {self}")

    def generate_presigned_put_url(self, url: str, expiration_time_seconds: int) -> str:
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
        raise NotImplementedError(f"URL signing is not supported by server for {self}")


class ActivityCaveat(enum.Enum):
    """Helper class for enumerating accepted activity caveats for requesting
    macaroons for dCache or XRootD webDAV servers.
    """

    DOWNLOAD = 1
    UPLOAD = 2


class DavClientURLSigner(DavClient):
    """WebDAV client which supports signing of URL for upload and download.

    Instances of this class are thread-safe.

    Parameters
    ----------
    url : `str`
        Root URL of the storage endpoint (e.g. "https://host.example.org:1234/")

    config : `DavConfig`
        Configuration to initialize this client.
    """

    def __init__(self, url: str, config: DavConfig, accepts_ranges: bool | None = None) -> None:
        super().__init__(url=url, config=config, accepts_ranges=accepts_ranges)

    def generate_presigned_get_url(self, url: str, expiration_time_seconds: int) -> str:
        """Return a pre-signed URL that can be used to retrieve the resource
        at `url` using an HTTP GET without supplying any access credentials.

        Parameters
        ----------
        url : `str`
            URL of an existing file.
        expiration_time_seconds : `int`
            Number of seconds until the generated URL is no longer valid.

        Returns
        -------
        url : `str`
            HTTP URL signed for GET.

        Notes
        -----
        Although the returned URL allows for downloading the file at `url`
        without supplying credentials, the HTTP client must be configured
        to accept the certificate the server will present if the client wants
        validate it. The server's certificate may be issued by a certificate
        authority unknown to the client.
        """
        macaroon: str = self._get_macaroon(url, ActivityCaveat.DOWNLOAD, expiration_time_seconds)
        return f"{url}?authz={macaroon}"

    def generate_presigned_put_url(self, url: str, expiration_time_seconds: int) -> str:
        """Return a pre-signed URL that can be used to upload a file to `url`
        using an HTTP PUT without supplying any access credentials.

        Parameters
        ----------
        url : `str`
            URL of an existing file.
        expiration_time_seconds : `int`
            Number of seconds until the generated URL is no longer valid.

        Returns
        -------
        url : `str`
            HTTP URL signed for PUT.

        Notes
        -----
        Although the returned URL allows for uploading a file to `url`
        without supplying credentials, the HTTP client must be configured
        to accept the certificate the server will present if the client wants
        validate it. The server's certificate may be issued by a certificate
        authority unknown to the client.
        """
        macaroon: str = self._get_macaroon(url, ActivityCaveat.UPLOAD, expiration_time_seconds)
        return f"{url}?authz={macaroon}"

    def _get_macaroon(self, url: str, activity: ActivityCaveat, expiration_time_seconds: int) -> str:
        """Return a macaroon for uploading or downloading the file at `url`.

        Parameters
        ----------
        url : `str`
            URL of an existing file.
        activity : `ActivityCaveat`
            the activity the macaroon is requested for.
        expiration_time_seconds : `int`
            Requested duration of the macaroon, in seconds.

        Returns
        -------
        macaroon : `str`
            Macaroon to be used with `url` in a GET or PUT request.
        """
        # dCache and XRootD webDAV servers support delivery of macaroons.
        #
        # For details about dCache macaroons see:
        #    https://www.dcache.org/manuals/UserGuide-9.2/macaroons.shtml
        match activity:
            case ActivityCaveat.DOWNLOAD:
                activity_caveat = "DOWNLOAD,LIST"
            case ActivityCaveat.UPLOAD:
                activity_caveat = "UPLOAD,LIST,DELETE,MANAGE"

        # Retrieve a macaroon for the requested activities and duration
        headers = {"Content-Type": "application/macaroon-request"}
        body = {
            "caveats": [
                f"activity:{activity_caveat}",
            ],
            "validity": f"PT{expiration_time_seconds}S",
        }
        resp = self._request("POST", url, headers=headers, body=json.dumps(body))
        if resp.status != HTTPStatus.OK:
            raise ValueError(
                f"Could not retrieve a macaroon for URL {resp.geturl()}, status: {resp.status} {resp.reason}"
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
            response_body = json.loads(resp.data.decode("utf-8"))
        except json.JSONDecodeError:
            raise ValueError(f"Could not deserialize response to POST request for URL {resp.geturl()}")

        if "macaroon" in response_body:
            return response_body["macaroon"]

        raise ValueError(f"Could not retrieve macaroon for URL {resp.geturl()}")

    def copy(self, source_url: str, destination_url: str, overwrite: bool = False) -> None:
        """Copy the file at `source_url` to `destination_url` in the same
        storage endpoint.

        Parameters
        ----------
        source_url : `str`
            URL of the source file.
        destination_url : `str`
            URL of the destination file. Its parent directory must exist.
        overwrite : `bool`
            If True and a file exists at `destination_url` it will be
            overwritten. Otherwise an exception is raised.
        """
        # Check the source is a file
        if self.stat(source_url).is_dir:
            raise NotImplementedError(f"copy is not implemented for directory {source_url}")

        # Neither dCache nor XrootD currently implement the COPY
        # webDAV method as documented in
        #
        #    http://www.webdav.org/specs/rfc4918.html#METHOD_COPY
        #
        # (See issues DM-37603 and DM-37651 for details)
        # With those servers use third-party copy instead.
        return self._copy_via_third_party(source_url, destination_url, overwrite)

    def _copy_via_third_party(self, source_url: str, destination_url: str, overwrite: bool = False) -> None:
        """Copy the file at `source_url` to `destination_url` in the same
        storage endpoint using the third-party copy functionality
        implemented by dCache and XRootD servers.

        Parameters
        ----------
        source_url : `str`
            URL of the source file.
        destination_url : `str`
            URL of the destination file. Its parent directory must exist.
        overwrite : `bool`
            If True and a file exists at `destination_url` it will be
            overwritten. Otherwise an exception is raised.
        """
        # To implement COPY we use dCache's third-party copy mechanism
        # documented at:
        #
        #    https://www.dcache.org/manuals/UserGuide-10.2/webdav.shtml#third-party-transfers
        #
        # The reason is that dCache does not correctly implement webDAV's COPY
        # method. See https://github.com/dCache/dcache/issues/6950

        # Retrieve a macaroon for downloading the source
        download_macaroon = self._get_macaroon(source_url, ActivityCaveat.DOWNLOAD, 300)

        # Prepare and send the COPY request
        try:
            headers = {
                "Source": source_url,
                "TransferHeaderAuthorization": f"Bearer {download_macaroon}",
                "Credential": "none",
                "Depth": "0",
                "Overwrite": "T" if overwrite else "F",
                "RequireChecksumVerification": "false",
            }
            resp = self._request("COPY", destination_url, headers=headers, preload_content=False)
            if resp.status == HTTPStatus.CREATED:
                return

            if resp.status != HTTPStatus.ACCEPTED:
                raise ValueError(
                    f"Unable to copy resource {resp.geturl()}; status: {resp.status} {resp.reason}"
                )

            content_type = resp.headers.get("Content-Type")
            if content_type != "text/perf-marker-stream":
                raise ValueError(
                    f"""Unexpected Content-Type {content_type} in response to COPY request from """
                    f"""{source_url} to {destination_url}"""
                )

            # Read the performance markers in the response body.
            # Documentation:
            #    https://dcache.org/manuals/UserGuide-10.2/webdav.shtml#third-party-transfers
            for marker in io.TextIOWrapper(resp):  # type: ignore
                marker = marker.rstrip("\n")
                if marker == "":  # EOF
                    raise ValueError(
                        f"""Copying file from {source_url} to {destination_url} failed: """
                        """could not get response from server"""
                    )
                elif marker.startswith("failure:"):
                    raise ValueError(
                        f"""Copying file from {source_url} to {destination_url} failed with error: """
                        f"""{marker}"""
                    )
                elif marker.startswith("success:"):
                    return
        finally:
            resp.drain_conn()


class DavClientDCache(DavClientURLSigner):
    """Client for interacting with a dCache webDAV server.

    Instances of this class are thread-safe.

    Parameters
    ----------
    url : `str`
        Root URL of the storage endpoint (e.g. "https://host.example.org:1234/")

    config : `DavConfig`
        Configuration to initialize this client.
    """

    def __init__(self, url: str, config: DavConfig, accepts_ranges: bool | None = None) -> None:
        super().__init__(url=url, config=config, accepts_ranges=accepts_ranges)

    def _propfind(self, url: str, body: str | None = None, depth: str = "0") -> HTTPResponse:
        """Send a HTTP PROPFIND request and return the response.

        Parameters
        ----------
        url : `str`
            Target URL.
        body : `str`, optional
            Request body.
        """
        if body is None:
            # Request only the DAV live properties we are explicitly interested
            # in namely 'resourcetype', 'getcontentlength', 'getlastmodified'
            # and 'displayname'. In addition, request dCache-specific
            # checksums.
            body = (
                """<?xml version="1.0" encoding="utf-8"?>"""
                """<D:propfind xmlns:D="DAV:" xmlns:dcache="http://www.dcache.org/2013/webdav"><D:prop>"""
                """<D:resourcetype/><D:getcontentlength/><D:getlastmodified/><D:displayname/>"""
                """<dcache:Checksums/>"""
                """</D:prop></D:propfind>"""
            )

        return super()._propfind(url=url, body=body, depth=depth)

    def _get(
        self, url: str, headers: dict[str, str] | None = None, preload_content: bool = True
    ) -> HTTPResponse:
        """Send a HTTP GET request to a dCache webDAV server.

        Parameters
        ----------
        url : `str`
            Target URL.
        headers : `dict[str, str]`, optional
            Headers to sent with the request.
        preload_content: `bool`, optional
            If True, the response body is downloaded and can be retrieved
            via the returned response `.data` property. If False, the
            caller needs to call the `.read()` on the returned response
            object to download the body.

        Returns
        -------
        resp: `HTTPResponse`
            Response to the GET request as received from the server.
        """
        # Send the GET request to the frontend servers. We handle
        # redirections ourselves.
        headers = {} if headers is None else dict(headers)
        resp = self._request("GET", url, headers=headers, preload_content=preload_content, redirect=False)
        if resp.status in (HTTPStatus.OK, HTTPStatus.PARTIAL_CONTENT):
            return resp

        if resp.status == HTTPStatus.NOT_FOUND:
            raise FileNotFoundError(f"No file found at {resp.geturl()}")

        redirect_location = resp.get_redirect_location()
        if redirect_location is None or redirect_location is False:
            raise ValueError(
                f"Unexpected error in HTTP GET {resp.geturl()}: status {resp.status} {resp.reason}"
            )

        # We were redirected to a backend server so follow the redirection.
        # The response body will be automatically downloaded when
        # `preload_content` is true and the underlying network connection
        # may be kept open for future reuse if the maximum number of
        # connections for the backend pool is not reached.
        try:
            # Explicitly ask the backend server to close the connection after
            # serving this request.
            if preload_content:
                headers.update({"Connection": "close"})

            url = redirect_location
            resp = self._request(
                "GET",
                url,
                headers=headers,
                pool_manager=self._backend,
                preload_content=preload_content,
            )

            # Mark this connection so that it won't be be automatically
            # returned to the reusable connection pool. We will close it
            # ourselves if appropriate.
            if preload_content:
                resp.auto_close = False

            if resp.status not in (HTTPStatus.OK, HTTPStatus.PARTIAL_CONTENT):
                raise ValueError(
                    f"Unexpected error in HTTP GET {resp.geturl()}: status {resp.status} {resp.reason}"
                )

            # The caller will access the `resp.data` property or use
            # the `resp.read()` method to read the contents of the
            # response body. If `preload_content` argument is True, the
            # response body is already downloaded, otherwise `resp.read()`
            # will download it.
            return resp
        finally:
            # Don't keep this connection to the backend server open. Given
            # that dCache pools may be configured to serve requests over a
            # range of ports, it is unlikely we will reuse this particular
            # connection again in the short term.
            if preload_content:
                resp.close()

    def _put(
        self,
        url: str,
        data: BinaryIO | bytes,
    ) -> None:
        """Send a HTTP PUT request to a dCache webDAV server.

        Parameters
        ----------
        url : `str`
            Target URL.
        data: `BinaryIO` or `bytes`
            Request body.
        """
        # Send a PUT request with empty body to the dCache frontend server to
        # get redirected to the backend.
        #
        # Details:
        # https://www.dcache.org/manuals/UserGuide-10.2/webdav.shtml#redirection
        #
        # Note that we use the backend pool manager for PUT requests, since
        # the dCache webDAV door closes the connection when redirecting a
        # PUT request to the backend.
        #
        # We want to reuse the connections to the door as much as possible so
        # that metadata operations are faster; all metadata operations use the
        # frontend pool manager.
        headers = {"Content-Length": "0", "Expect": "100-continue"}
        resp = self._request("PUT", url, headers=headers, redirect=False, pool_manager=self._backend)
        if redirect_location := resp.get_redirect_location():
            url = redirect_location
        elif resp.status not in (
            HTTPStatus.OK,
            HTTPStatus.CREATED,
            HTTPStatus.NO_CONTENT,
        ):
            raise ValueError(
                f"""Unexpected response to HTTP request PUT {resp.geturl()}: status {resp.status} """
                f"""{resp.reason} [{resp.data.decode("utf-8")}]"""
            )

        # We were redirected to a backend server. Upload the file contents to
        # its final destination. Explicitly ask the server to close this
        # network connection after serving this PUT request to release
        # the associated dCache mover.

        # Ask dCache to compute and record a checksum of the uploaded
        # file contents, for later integrity checks. Since we don't compute
        # the digest ourselves while uploading the data, we cannot control
        # after the request is complete that the data we uploaded is
        # identical to the data recorded by the server, but at least the
        # server has recorded a digest of the data it stored.
        #
        # See RFC-3230 for details and
        # https://www.iana.org/assignments/http-dig-alg/http-dig-alg.xhtml
        # for the list of supported digest algorithhms.
        headers = {"Connection": "close"}
        if (checksum := self._config.request_checksum) is not None:
            headers.update({"Want-Digest": checksum})

        try:
            resp = self._request(
                "PUT",
                url,
                body=data,
                headers=headers,
                pool_manager=self._backend,
                # Don't consume the response body, so that we can explicitly
                # close the connection.
                preload_content=False,
            )

            # Disable automatically returning the connection to the pool
            # to be reused later on, since we want that connection to be
            # closed. By default, when preload_content is True, the network
            # connection is returned to the connection pool once the response
            # body is completely consumed. Once this happens, we don't have a
            # mecanism to force closing the connection.
            resp.auto_close = False

            if resp.status not in (
                HTTPStatus.OK,
                HTTPStatus.CREATED,
                HTTPStatus.NO_CONTENT,
            ):
                raise ValueError(
                    f"""Unexpected response to HTTP request PUT {resp.geturl()}: status {resp.status} """
                    f"""{resp.reason} [{resp.data.decode("utf-8")}]"""
                )

        finally:
            # Explicitly close this connection to the dCache backend server.
            resp.close()

    def download(self, url: str, filename: str, chunk_size: int, close_connection: bool = True) -> int:
        # Close the connection to the backend servers after downloading
        # the entire file content.
        return super().download(
            url=url, filename=filename, chunk_size=chunk_size, close_connection=close_connection
        )


class DavClientXrootD(DavClientURLSigner):
    """Client for interacting with a XrootD webDAV server.

    Instances of this class are thread-safe.

    Parameters
    ----------
    url : `str`
        Root URL of the storage endpoint (e.g. "https://host.example.org:1234/")

    config : `DavConfig`
        Configuration to initialize this client.
    """

    def __init__(self, url: str, config: DavConfig, accepts_ranges: bool | None = None) -> None:
        super().__init__(url=url, config=config, accepts_ranges=accepts_ranges)

    def _get(
        self, url: str, headers: dict[str, str] | None = None, preload_content: bool = True
    ) -> HTTPResponse:
        """Send a HTTP GET request to a XrootD webDAV server.

        Parameters
        ----------
        url : `str`
            Target URL.
        headers : `dict[str, str]`, optional
            Headers to sent with the request.
        preload_content: `bool`, optional
            If True, the response body is downloaded and can be retrieved
            via the returned response `.data` property. If False, the
            caller needs to call the `.read()` on the returned response
            object to download the body.

        Returns
        -------
        resp: `HTTPResponse`
            Response to the GET request as received from the server.
        """
        # Send the GET request to the frontend servers and follow redirection.
        headers = {} if headers is None else dict(headers)
        resp = self._request("GET", url, headers=headers, preload_content=preload_content, redirect=False)
        if resp.status in (HTTPStatus.OK, HTTPStatus.PARTIAL_CONTENT):
            return resp

        if resp.status == HTTPStatus.NOT_FOUND:
            raise FileNotFoundError(f"No file found at {resp.geturl()}")

        redirect_location = resp.get_redirect_location()
        if redirect_location is None or redirect_location is False:
            raise ValueError(
                f"Unexpected error in HTTP GET {resp.geturl()}: status {resp.status} {resp.reason}"
            )

        # We were redirected to a backend server so follow the redirection.
        # The response body will be automatically downloaded when
        # `preload_content` is true and the underlying network connection
        # may be kept open for future reuse if the maximum number of
        # connections for the backend pool is not reached.
        #
        # For XRootD endpoints, we always use the same pool manager, namely
        # the frontend pool manager, to increase the chance of reusing
        # network connections.
        url = redirect_location
        resp = self._request(
            "GET",
            url,
            headers=headers,
            pool_manager=self._frontend,
            preload_content=preload_content,
        )

        if resp.status not in (HTTPStatus.OK, HTTPStatus.PARTIAL_CONTENT):
            resp.close()
            raise ValueError(
                f"Unexpected error in HTTP GET {resp.geturl()}: status {resp.status} {resp.reason}"
            )

        # The caller will access the `resp.data` property or use
        # the `resp.read()` method to read the contents of the
        # response body. If `preload_content` argument is True, the
        # response body is already downloaded, otherwise `resp.read()`
        # will download it.
        return resp

    def _put(
        self,
        url: str,
        data: BinaryIO | bytes,
    ) -> None:
        """Send a HTTP PUT request to a dCache webDAV server.

        Parameters
        ----------
        url : `str`
            Target URL.
        data: `BinaryIO` or `bytes`
            Request body.
        """
        # Send a PUT request with empty body to the XRootD frontend server to
        # get redirected to the backend.
        headers = {"Content-Length": "0", "Expect": "100-continue"}
        for attempt in range(max_attempts := 3):
            resp = self._request("PUT", url, headers=headers, redirect=False)
            if redirect_location := resp.get_redirect_location():
                url = redirect_location
                break
            elif resp.status == HTTPStatus.LOCKED:
                # Sometimes XRootD servers respond with status code LOCKED and
                # response body of the form:
                #
                # "Output file /path/to/file is already opened by 1 writer;
                # open denied."
                #
                # If we get such a response, try again, unless we reached
                # the maximum number of attempts.
                if attempt == max_attempts - 1:
                    raise ValueError(
                        f"""Unexpected response to HTTP request PUT {resp.geturl()}: status {resp.status} """
                        f"""{resp.reason} [{resp.data.decode("utf-8")}] after {max_attempts} attempts"""
                    )

                # Wait a bit and try again
                log.warning(
                    f"""got unexpected response status {HTTPStatus.LOCKED} Locked for {url} """
                    f"""(attempt {attempt}/{max_attempts}), retrying..."""
                )
                time.sleep((attempt + 1) * 0.100)
                continue
            elif resp.status not in (
                HTTPStatus.OK,
                HTTPStatus.CREATED,
                HTTPStatus.NO_CONTENT,
            ):
                raise ValueError(
                    f"""Unexpected response to HTTP request PUT {resp.geturl()}: status {resp.status} """
                    f"""{resp.reason} [{resp.data.decode("utf-8")}]"""
                )

        # We were redirected to a backend server. Upload the file contents to
        # its final destination.

        # XRootD backend servers typically use a single port number for
        # accepting connections from clients. It is therefore beneficial
        # to keep those connections open, if the server allows.

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
        #
        # In addition, note that not all servers implement this RFC so
        # the checksum reqquest may be ignored by the server.
        headers = {}
        if (checksum := self._config.request_checksum) is not None:
            headers = {"Want-Digest": checksum}

        # For XRootD endpoints, we always use the same pool manager, namely
        # the frontend pool manager, to increase the chance of reusing
        # network connections.
        resp = self._request(
            "PUT",
            url,
            body=data,
            headers=headers,
            pool_manager=self._frontend,
        )

        if resp.status not in (
            HTTPStatus.OK,
            HTTPStatus.CREATED,
            HTTPStatus.NO_CONTENT,
        ):
            raise ValueError(
                f"""Unexpected response to HTTP request PUT {resp.geturl()}: status {resp.status} """
                f"""{resp.reason} [{resp.data.decode("utf-8")}]"""
            )

    def info(self, url: str, name: str | None = None) -> dict[str, Any]:
        # XRootD does not include checksums in the response to PROPFIND
        # requqest. We need to send a specific HEAD request to retrieve
        # the ADLER32 checksum.
        #
        # If found, the checksum is included in the response header "Digest",
        # which is of the form:
        #
        #    Digest: adler32=0e4709f2
        result = super().info(url, name)
        if result["type"] == "file":
            headers: dict[str, str] = {"Want-Digest": "adler32"}
            resp = self._head(url=url, headers=headers)
            if (digest := resp.headers.get("Digest")) is not None:
                value = digest.split("=")[1]
                result["checksums"].update({"adler32": value})

        return result


class DavFileMetadata:
    """Container for attributes of interest of a webDAV file or directory."""

    def __init__(
        self,
        base_url: str,
        href: str = "",
        name: str = "",
        exists: bool = False,
        size: int = -1,
        is_dir: bool = False,
        last_modified: datetime = datetime.min,
        checksums: dict[str, str] | None = None,
    ):
        self._url: str = base_url if not href else base_url.rstrip("/") + href
        self._href: str = href
        self._name: str = name
        self._exists: bool = exists
        self._size: int = size
        self._is_dir: bool = is_dir
        self._last_modified: datetime = last_modified
        self._checksums: dict[str, str] = {} if checksums is None else dict(checksums)

    @staticmethod
    def from_property(base_url: str, property: DavProperty) -> DavFileMetadata:
        """Create an instance from the values in `property`."""
        return DavFileMetadata(
            base_url=base_url,
            href=property.href,
            name=property.name,
            exists=property.exists,
            size=property.size,
            is_dir=property.is_dir,
            last_modified=property.last_modified,
            checksums=dict(property.checksums),
        )

    def __str__(self) -> str:
        return (
            f"""{self._url} {self._href} {self._name}  {self._exists} {self._size} {self._is_dir} """
            f"""{self._checksums}"""
        )

    @property
    def url(self) -> str:
        return self._url

    @property
    def href(self) -> str:
        return self._href

    @property
    def name(self) -> str:
        return self._name

    @property
    def exists(self) -> bool:
        return self._exists

    @property
    def size(self) -> int:
        if not self._exists:
            return -1

        return 0 if self._is_dir else self._size

    @property
    def is_dir(self) -> bool:
        return self._exists and self._is_dir

    @property
    def is_file(self) -> bool:
        return self._exists and not self._is_dir

    @property
    def last_modified(self) -> datetime:
        return self._last_modified

    @property
    def checksums(self) -> dict[str, str]:
        return self._checksums


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
        self._checksums: dict[str, str] = {}

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

                # Parse "Checksums"
                if (element := prop.find("./{http://www.dcache.org/2013/webdav}Checksums")) is not None:
                    self._checksums = self._parse_checksums(element.text)

        # Some webDAV servers don't include the 'displayname' property in the
        # response so try to infer it from the value of the 'href' property.
        # Depending on the server the href value may end with '/'.
        if not self._displayname:
            self._displayname = os.path.basename(self._href.rstrip("/"))

        # Some webDAV servers do not append a "/" to the href of directories.
        # Ensure we include a single final "/" in our response.
        if self._collection:
            self._href = self._href.rstrip("/") + "/"

        # Force a size of 0 for collections.
        if self._collection:
            self._getcontentlength = 0

    def _parse_checksums(self, checksums: str | None) -> dict[str, str]:
        # checksums argument is of the form
        #    md5=MyS/wljSzI9WYiyrsuyoxw==,adler32=23b104f2
        result: dict[str, str] = {}
        if checksums is not None:
            for checksum in checksums.split(","):
                if (pos := checksum.find("=")) != -1:
                    algorithm, value = checksum[:pos].lower(), checksum[pos + 1 :]
                    if algorithm == "md5":
                        # dCache documentation about how it encodes the
                        # MD5 checksum:
                        #
                        # https://www.dcache.org/manuals/UserGuide-10.2/webdav.shtml#checksums
                        result[algorithm] = bytes.hex(base64.standard_b64decode(value))
                    else:
                        result[algorithm] = value

        return result

    @property
    def exists(self) -> bool:
        # It is either a directory or a file with length of at least zero
        return self._collection or self._getcontentlength >= 0

    @property
    def is_dir(self) -> bool:
        return self._collection

    @property
    def is_file(self) -> bool:
        return not self._collection

    @property
    def last_modified(self) -> datetime:
        if not self._getlastmodified:
            return datetime.min

        # Last modified timestamp is of the form:
        # 'Wed, 12 Mar 2025 10:11:13 GMT'
        return datetime.strptime(self._getlastmodified, "%a, %d %b %Y %H:%M:%S %Z")

    @property
    def size(self) -> int:
        return self._getcontentlength

    @property
    def name(self) -> str:
        return self._displayname

    @property
    def href(self) -> str:
        return self._href

    @property
    def checksums(self) -> dict[str, str]:
        return self._checksums


class DavPropfindParser:
    """Helper class to parse the response body of a PROPFIND request.

    Parameters
    ----------
    body : `bytes`
        The XML-encoded response body to PROPFIND.
    """

    def __init__(self) -> None:
        return

    def parse(self, body: bytes) -> list[DavProperty]:
        """Parse the XML-encoded contents of the response body to a webDAV
        PROPFIND request.

        Parameters
        ----------
        body : `bytes`
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
        decoded_body: str = body.decode("utf-8").strip()
        responses = []
        multistatus = eTree.fromstring(decoded_body)
        for response in multistatus.findall("./{DAV:}response"):
            responses.append(DavProperty(response))

        if responses:
            return responses
        else:
            # Could not parse the body
            raise ValueError(f"Unable to parse response for PROPFIND request: {decoded_body}")


class TokenAuthorizer:
    """Attach a bearer token 'Authorization' header to each request.

    Parameters
    ----------
    token : `str`
        Can be either the path to a local file which contains the
        value of the token or the token itself. If `token` is a file
        it must be protected so that only the owner can read and write it.
    """

    def __init__(self, token: str | None = None) -> None:
        self._token = self._path = None
        self._mtime: float = -1.0
        if token is None:
            return

        self._token = token
        if os.path.isfile(token):
            self._path = os.path.abspath(token)
            if not self._is_protected(self._path):
                raise PermissionError(
                    f"""Authorization token file at {self._path} must be protected for access only """
                    """by its owner"""
                )
            self._refresh()

    def _refresh(self) -> None:
        """Read the token file (if any) if its modification time is more recent
        than the last time we read it.
        """
        if self._path is None:
            return

        if (mtime := os.stat(self._path).st_mtime) > self._mtime:
            log.debug("Reading authorization token from file %s", self._path)
            self._mtime = mtime
            with open(self._path) as f:
                self._token = f.read().rstrip("\n")

    def _is_protected(self, filepath: str) -> bool:
        """Return true if the permissions of file at filepath only allow for
        access by its owner.

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

    def set_authorization(self, headers: dict[str, str]) -> None:
        """Add the 'Authorization' header to `headers`."""
        if self._token is None:
            return

        self._refresh()
        headers["Authorization"] = f"Bearer {self._token}"


def expand_vars(path: str | None) -> str | None:
    """Expand the environment variables in `path` and return the path with
    the value of the variable expanded.

    Parameters
    ----------
    path : `str` or `None`
       Abolute or relative path which may include an environment variable
       e.g. '$HOME/path/to/my/file'

    Returns
    -------
    path: `str`
        The path with the values of the environment variables expanded.
    """
    return None if path is None else os.path.expandvars(path)


def dump_response(method: str, resp: HTTPResponse) -> None:
    """Dump response for debugging purposes."""
    log.debug("%s %s", method, resp.geturl())
    for header, value in resp.headers.items():
        log.debug("   %s: %s", header, value)
    log.debug("   response body length: %d", len(resp.data.decode("utf-8")))
