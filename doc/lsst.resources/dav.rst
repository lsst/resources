webDAV ResourcePath
===================

The basic syntax for using a webDAV `~lsst.resources.ResourcePath` is:

.. code-block::

    ResourcePath("davs://host.example.org:1234/path/to/file")

Configuration
-------------
Interacting with WebDAV servers may require specific client configuration.
That is for instance the case when the server exposes a host certificate
which is not issued by a certificate authority trusted by the system where
the client runs. Another case is when the server requires the client
presents its identity for authentication purposes.

In order to configure `~lsst.resources.ResourcePath` to interact with one or
more WebDAV servers which require specific configuration, you must initialize
the environment variable ``LSST_RESOURCES_WEBDAV_CONFIG`` to point to a
configuration YAML file. This configuration file must contain the settings for
each of the webDAV servers which host any of the
`~lsst.resources.ResourcePath` objects with ``davs://`` or ``dav://`` scheme
you need to instantiate.

The general structure of the configuration file is as follows:

.. code-block:: yaml

    # These settings apply to all ResourcePath objects hosted by
    # server 'host.example.org:1234'.
    - base_url: "davs://host.example.org:1234/"
      user_cert: "${X509_USER_PROXY}"
      trusted_authorities: "/etc/grid-security/certificates"

    # These settings apply to all ResourcePath objects hosted by
    # server 'host.domain.org:5432'.
    - base_url: "davs://host.domain.org:5432/"
      token: "${HOME}/.token"

    # These settings apply to all ResourcePath objects hosted by
    # server 'webdav.example.org:9876'.
    - base_url: "davs://webdav.example.org:9876/"
      timeout_connect: 30.0
      timeout_read: 120.0
      retries: 5

For each WebDAV endpoint you can specify several settings that all instances
of `~lsst.resources.ResourcePath` hosted at that specific endpoint will use.
If no settings are found in the configuration for a given endpoint, sensible
defaults values are used (see below).

Please note that if your WebDAV endpoint requires client authentication you
must have an entry for that endpoint in your configuration file. Currently
two client authentication mechanisms are supported: either a client
X.509 certificate (and associated private key) or a token. If both are
specified, token authentication is preferred.

Similarly, if the WebDAV server exposes a host certificate that is not
issued by a certification authority trusted by the operating system where
your client runs, you must add an entry for that endpoint to the configuration
file which includes the local path to the file or directory where the trusted
authorities can be found.

Configuration settings
^^^^^^^^^^^^^^^^^^^^^^
These are the settings you can specify in the configuration file for each
WebDAV endpoint:

``user_cert``
    Path to the client certificate the WebDAV client must present to the
    server for authentication purposes.

    If not specified, no client certificate is presented to the server.

    This setting is ignored if ``token`` is specified (see below).

``user_key``
    Path to the private key associated to the client certificate the WebDAV
    client must present to the server for authentication purposes.

    If not specified but ``user_cert`` is specified, it is assumed that
    the private key and the user certificate are both in the same file
    specified in the value for ``user_cert``.

``trusted_authorities``
    Path to a local directory or certificate bundle file where the
    certificates of the trusted certificate authorities can be found.
    Those certificates will be used by the client of the WebDAV endpoint
    to verify the server's host certificate.

    If not specified, the certificates trusted by the system are used. The
    server's host certificate is always verified.

``token``
    Value of the token the WebDAV client must sent to the server for
    authentication purposes. The value of this entry may be the token itself
    or the path to a local file where the value of the token can be found. It
    is however discouraged to specify the token value directly in the
    configuration file. Instead store the value of the token in a protected
    file and specify the path to that file as the value of this entry.

    If ``token`` is specified that mechanism is preferred for authentication
    of client requests, even if ``user_cert`` is also specified.

    If you specify a value for ``token`` which is the path to a local file
    which contains the actual token, that file must be protected for
    reading and writing only by its owner. The contents of that file is
    automatically reloaded when every time it is modified.

``timeout_connect``
    Timeout in seconds to establish a network connection with the remote
    server.

    Default: 10 seconds (``float``).

``timeout_read``
    Timeout in seconds to read the response to a request sent to the server.
    This is total time for reading both the headers and the response body.
    It must be large enough to allow for upload and download of files
    of typical size.

    Default: 300 seconds (``float``).

``retries``
    Number of times to retry requests before failing. Retry happens only
    under certain conditions.

    Default: 3 (``int``).

``retry_backoff_min``
    Minimal retry backoff (in seconds) for the client to compute
    the wait time before retrying a request.
    A value in the interval [``retry_backoff_min``, ``retry_backoff_max``]
    is randomly selected as the backoff factor every time a request is
    retried.

    Default: 1.0 seconds (``float``).

``retry_backoff_max``
    Maximum retry backoff (in seconds) for the client to compute
    the wait time before retrying a request.
    A value in the interval [``retry_backoff_min``, ``retry_backoff_max``]
    is randomly selected as the backoff factor every time a request is
    retried.

    Default: 3.0 seconds (``float``).

``buffer_size``
    Size of the buffer (in mebibytes, i.e. 1024*1024 bytes) the WebDAV
    client of this endpoint will use when sending requests and receiving
    responses.

    Default: 5 mebibytes (``int``).

``persistent_connections_frontend``
    Maximum number of network connections to persist against each one of
    the hosts in the server frontend.

    Default: 50 (``int``).

``persistent_connections_backend``
    Maximum number of network connections to persist against each one of
    the hosts in the server backend.

    Default: 100 (``int``).

``enable_fsspec``
    If specified, expose a `fsspec <https://filesystem-spec.read>`_-compatible,
    read-only file system for accessing a  `~lsst.resources.ResourcePath`
    object.

    Default: ``true`` (``boolean``).

``request_checksum``
    If specified, the WebDAV client will request the server to compute
    a checksum of the file contents every time a file is uploaded.

    Note that it is the server decision to compute the checksum. Some
    servers simply ignore that request.

    Accepted values: ``adler32``, ``md5``,  ``sha-256``, ``sha-512``.

``collect_memory_usage``
    If specified, memory usage data is collected when running in debug mode.
    Collecting memory usage data is expensive, so this setting should not
    be used in production.

    Accepted values: ``true``,  ``false``.

    Default: ``false`` (``boolean``).


Configuration Examples
----------------------

These are examples of configuration files for
`dCache <https://www.dcache.org>`_ and `XRootD <https://xrootd.org>`_ WebDAV
servers.

Set the environment variable ``LSST_RESOURCES_WEBDAV_CONFIG`` to point to
your configuration file:

.. code-block:: bash

    export LSST_RESOURCES_WEBDAV_CONFIG="${HOME}/.lsst/dav_conf.yaml"


dCache
^^^^^^

Typical configuration settings for a **dCache** endpoint are:

.. code-block:: yaml

    - base_url: "davs://dcache.example.org:2880/"
      trusted_authorities: "/etc/grid-security/certificates"
      user_cert: "${X509_USER_PROXY}"
      request_checksum: "md5"

The example above uses X.509 grid proxy client authentication. If you prefer
to use a token use instead:

.. code-block:: yaml

    - base_url: "davs://dcache.example.org:2880/"
      trusted_authorities: "/etc/grid-security/certificates"
      request_checksum: "md5"
      token: "${HOME}/.lsst/dcache_token"

and ensure the file at path ``${HOME}/.lsst/dcache_token`` contains the
client authentication token and is only readable and writable by you.

In this example we configure `~lsst.resources.ResourcePath` to request the
dCache server to compute and record the MD5 checksum when a file is uploaded,
in addition to the ADLER32 checksum dCache always computes and records for
each file.

XRootD
^^^^^^

Typical configuration settings for a **XRootD** endpoint are:

.. code-block:: yaml

    - base_url: "davs://xrootd.example.org:1094/"
      trusted_authorities: "/etc/grid-security/certificates"
      user_cert: "${X509_USER_PROXY}"

If you prefer to use a token for client authentication use the ``token``
setting instead (see dCache example above).
