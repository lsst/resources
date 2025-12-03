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

__all__ = ("DavResourcePath",)

import contextlib
import datetime
import functools
import io
import logging
import os
import re
import threading
import urllib
from collections.abc import Iterator
from typing import TYPE_CHECKING, Any, BinaryIO, cast, override

try:
    import fsspec
    from fsspec.spec import AbstractFileSystem
except ImportError:
    fsspec = None
    AbstractFileSystem = type

from ._resourceHandles import ResourceHandleProtocol
from ._resourceHandles._davResourceHandle import DavReadResourceHandle
from ._resourcePath import ResourcePath, ResourcePathExpression
from .davutils import (
    DavClient,
    DavClientPool,
    DavConfigPool,
    DavFileMetadata,
    normalize_path,
    normalize_url,
    redact_url,
)
from .utils import get_tempdir

if TYPE_CHECKING:
    from .utils import TransactionProtocol


log = logging.getLogger(__name__)


@functools.lru_cache
def _calc_tmpdir_buffer_size(tmpdir: str) -> int:
    """Compute the block size to use for writing files in `tmpdir` as
    256 blocks of typical size (i.e. 4096 bytes) or 10 times the file system
    block size, whichever is higher.

    This is a reasonable compromise between using memory for buffering and
    the number of system calls issued to read from or write to temporary
    files.
    """
    fsstats = os.statvfs(tmpdir)
    return max(10 * fsstats.f_bsize, 256 * 4096)


class DavResourcePathConfig:
    """Configuration class to encapsulate the configurable items used by
    all instances of class `DavResourcePath`.

    Instantiating this class creates a thread-safe singleton.
    """

    _instance = None
    _lock = threading.Lock()

    def __new__(cls) -> DavResourcePathConfig:
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)

        return cls._instance

    def __init__(self) -> None:
        # Path to the local temporary directory all instances of
        # `DavResourcePath` must use and its associated buffer size (in bytes).
        self._tmpdir_buffersize: tuple[str, int] | None = None

    @property
    def tmpdir_buffersize(self) -> tuple[str, int]:
        """Return the path to a temporary directory and the preferred buffer
        size to use when reading/writing files from/to that directory.
        """
        if self._tmpdir_buffersize is not None:
            return self._tmpdir_buffersize

        # Retrieve and cache the path and the blocksize for the temporary
        # directory if no other thread has done that in the meantime.
        with DavResourcePathConfig._lock:
            if self._tmpdir_buffersize is None:
                tmpdir = get_tempdir()
                bufsize = _calc_tmpdir_buffer_size(tmpdir)
                self._tmpdir_buffersize = (tmpdir, bufsize)

        return self._tmpdir_buffersize

    def _destroy(self) -> None:
        """Destroy this class singleton instance.

        Helper method to be used in tests to reset global configuration.
        """
        with DavResourcePathConfig._lock:
            DavResourcePathConfig._instance = None


class DavGlobals:
    """Helper container to encapsulate all the gloal objects needed by this
    module.
    """

    def __init__(self) -> None:
        # Client pool used by all DavResourcePath instances.
        # Use Any as type annotation to keep mypy happy.
        self._client_pool: Any = None

        # Configuration used by all DavResourcePath instances.
        self._config: Any = None

        # (Re)Initialize the objects above.
        self._reset()

    def _reset(self) -> None:
        """
        Initialize all the globals.

        This method is a helper for reinitializing globals in tests.
        """
        # Initialize the singleton instance of the webdav endpoint
        # configuration pool.
        config_pool: DavConfigPool = DavConfigPool("LSST_RESOURCES_WEBDAV_CONFIG")

        # Initialize the singleton instance of the webdav client pool. This is
        # a thread-safe singleton shared by all instances of DavResourcePath.
        if self._client_pool is not None:
            self._client_pool._destroy()

        self._client_pool = DavClientPool(config_pool)

        # Initialize the singleton instance of the configuration shared
        # all DavResourcePath objects.
        if self._config is not None:
            self._config._destroy()

        self._config = DavResourcePathConfig()

    def client_pool(self) -> DavClientPool:
        """Return the pool of reusable webDAV clients."""
        return self._client_pool

    def config(self) -> DavResourcePathConfig:
        """Return the configuration settings for all `DavResourcePath`
        objects.
        """
        return self._config


# Convenience object to encapsulate all global objects needed by this module.
dav_globals: DavGlobals = DavGlobals()


class DavResourcePath(ResourcePath):
    """WebDAV resource.

    Parameters
    ----------
    uri : `ResourcePathExpression`
        URI to store in object.
    root : `str` or `ResourcePath` or `None`, optional
        Root for relative URIs. Not used in this constructor.
    forceAbsolute : `bool`
        Whether to force absolute URI. A WebDAV URI is always absolute.
    forceDirectory : `bool` or `None`, optional
        Whether this URI represents a directory.
    isTemporary : `bool` or `None`, optional
        Whether this URI represents a temporary resource.
    """

    def __init__(
        self,
        uri: ResourcePathExpression,
        root: str | ResourcePath | None = None,
        forceAbsolute: bool = True,
        forceDirectory: bool | None = None,
        isTemporary: bool | None = None,
    ) -> None:
        # Build the internal URL we use to talk to the server, which
        # uses "http" or "https" as scheme instead of "dav" or "davs".
        self._internal_url: str = normalize_url(self.geturl())

        # WebDAV client this path must use to interact with the server.
        self._dav_client: DavClient | None = None

        # Retrieve the configuration shared by all instances of this class.
        self._config: DavResourcePathConfig = dav_globals.config()

        log.debug("created instance of DavResourcePath %s [%d]", self, id(self))

    @classmethod
    def _fixupPathUri(
        cls,
        parsed: urllib.parse.ParseResult,
        root: ResourcePath | None = None,
        forceAbsolute: bool = False,
        forceDirectory: bool | None = None,
    ) -> tuple[urllib.parse.ParseResult, bool | None]:
        """Correct any issues with the supplied URI.

        This function ensures that the path of the URI is normalized.
        """
        # Call the superclass' _fixupPathUri.
        parsed, dirLike = super()._fixupPathUri(parsed, forceDirectory=forceDirectory)

        # Clean the URL's path and ensure dir-like paths end by "/".
        path = normalize_path(parsed.path)
        if dirLike and path != "/":
            path += "/"

        return parsed._replace(path=path), dirLike

    @property
    def _client(self) -> DavClient:
        """Return the webDAV client for this resource."""
        # If we already have a client, use it.
        if self._dav_client is not None:
            return self._dav_client

        # Retrieve the client this resource must use to interact with the
        # server from the global client pool.
        self._dav_client = dav_globals.client_pool().get_client_for_url(self._internal_url)
        return self._dav_client

    def _stat(self) -> DavFileMetadata:
        """Retrieve metadata about this resource."""
        return self._client.stat(self._internal_url)

    def _exists_and_size(self) -> tuple[bool, bool, int]:
        """Return frequently used metadata of resource at `url`.

        Parameters
        ----------
        url : `str`
            Target URL.

        Returns
        -------
        is_dir: `bool`
           True if the resource at `url` exists and is a directory.
        is_file: `bool`
           True if the resource at `url` exists and is a file.
        size: `int`
           The size in bytes of the resource at `url` if it exists. The size
           of a directory is always zero.

        Notes
        -----
        The returned is_dir and is_file cannot be both True.
        """
        return self._client.exists_and_size(self._internal_url)

    def _exists_and_is_file(self) -> bool:
        """Return True if this resource exists and is a file."""
        _, is_file, _ = self._exists_and_size()
        return is_file

    @override
    def __str__(self) -> str:
        """Return this resource's redacted URL."""
        return redact_url(self.geturl())

    @override
    def mkdir(self) -> None:
        """Create the directory resource if it does not already exist."""
        log.debug("mkdir %s [%d]", self, id(self))

        if not self.isdir():
            raise NotADirectoryError(f"Can not create a directory for file-like URI {self}")

        if self._exists_and_is_file():
            # A file exists at this path.
            raise NotADirectoryError(
                f"Can not create a directory for {self} because a file already exists at that URL"
            )

        # The underlying webDAV client will use the knowledge it has about
        # the specific server to create the requested directory
        # hierarchy by issueing the minimum possible number of requests.
        self._client.mkcol(self._internal_url)

    @override
    def exists(self) -> bool:
        """Check that this resource exists."""
        log.debug("exists %s [%d]", self, id(self))

        is_dir, is_file, _ = self._exists_and_size()
        return is_dir or is_file

    @override
    def size(self) -> int:
        """Return the size of the remote resource in bytes."""
        log.debug("size %s [%d]", self, id(self))

        if self.isdir():
            return 0

        is_dir, is_file, file_size = self._exists_and_size()
        if not is_dir and not is_file:
            raise FileNotFoundError(f"No file or directory found at {self}")

        return file_size

    def info(self) -> dict[str, Any]:
        """Return metadata details about this resource."""
        log.debug("info %s [%d]", self, id(self))

        return self._client.info(self._internal_url, name=str(self))

    @override
    def read(self, size: int = -1) -> bytes:
        """Open the resource and return the contents in bytes.

        Parameters
        ----------
        size : `int`, optional
            The number of bytes to read. Negative or omitted indicates that
            all data should be read.
        """
        log.debug("read %s [%d] size=%d", self, id(self), size)

        # A GET request on a dCache directory returns the contents of the
        # directory in HTML, to be visualized with a browser. This means
        # that we need to check first that this resource is not a directory.
        #
        # Since isdir() only checks that the URL of the resource ends in "/"
        # without actually asking the server, this check is not robust.
        # However, it is a reasonable compromise since it prevents doing
        # an additional roundtrip to the server to retrieve this resource's
        # metadata.
        if self.isdir():
            raise ValueError(f"method read() is not implemented for directory {self}")

        if size < 0:
            # Read the entire file content
            _, data = self._client.read(self._internal_url)
            return data

        # This is a partial read. Retrieve the file size.
        _, is_file, file_size = self._exists_and_size()
        if not is_file:
            raise FileNotFoundError(f"No file found at {self}")

        if size == 0 or file_size == 0:
            return b""

        # Read the requested chunk of data. The connection to the backend
        # server may be released if the client decides it is beneficial
        # for the specific server it interacts with.
        end_range = min(file_size, size) - 1
        _, data = self._client.read_range(self._internal_url, start=0, end=end_range)
        return data

    @override
    @contextlib.contextmanager
    def _as_local(
        self, multithreaded: bool = True, tmpdir: ResourcePath | None = None
    ) -> Iterator[ResourcePath]:
        """Download object and place in temporary directory.

        Parameters
        ----------
        multithreaded : `bool`, optional
            If `True` the transfer will be allowed to attempt to improve
            throughput by using parallel download streams. This may of no
            effect if the URI scheme does not support parallel streams or
            if a global override has been applied. If `False` parallel
            streams will be disabled.
        tmpdir : `ResourcePath` or `None`, optional
            Explicit override of the temporary directory to use for remote
            downloads.

        Returns
        -------
        local_uri : `ResourcePath`
            A URI to a local POSIX file corresponding to a local temporary
            downloaded copy of the resource.
        """
        # We need to ensure that this resource is actually a file since
        # the response to a GET request on a directory may be implemented in
        # several ways, according to RFC 4818.
        if not self._exists_and_is_file():
            raise FileNotFoundError(f"No file found at {self}")

        if tmpdir is None:
            local_dir, buffer_size = self._config.tmpdir_buffersize
            tmpdir = ResourcePath(local_dir, forceDirectory=True)
        else:
            buffer_size = _calc_tmpdir_buffer_size(tmpdir.ospath)

        with ResourcePath.temporary_uri(suffix=self.getExtension(), prefix=tmpdir, delete=True) as tmp_uri:
            self._client.download(self._internal_url, tmp_uri.ospath, buffer_size)
            yield tmp_uri

    @override
    def write(self, data: BinaryIO | bytes, overwrite: bool = True) -> None:
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
        log.debug("write %s [%d] overwrite=%s", self, id(self), overwrite)

        if self.isdir():
            raise ValueError(f"Method write() is not implemented for directory {self}")

        if not overwrite and self._exists_and_is_file():
            raise FileExistsError(f"File {self} exists and overwrite has been disabled")

        self._client.write(self._internal_url, data)

    @override
    def remove(self) -> None:
        """Remove the resource.

        If the resource is a directory, it must be empty otherwise this
        method raises. Removing a non-existent file or directory is not
        considered an error.
        """
        log.debug("remove %s [%d]", self, id(self))

        is_dir, is_file, _ = self._exists_and_size()
        if not is_dir and not is_file:
            # There is no resource at this uri. There is nothing to do.
            return

        if is_dir:
            entries = self._client.read_dir(self._internal_url)
            if len(entries) > 0:
                raise IsADirectoryError(f"Directory {self} is not empty")

        # This resource is a either file or an empty directory, we can remove
        # it.
        self._client.delete(self._internal_url)

    def remove_dir(self, recursive: bool = False) -> None:
        """Remove a directory if empty.

        Parameters
        ----------
        recursive : `bool`
            If `True` recursively remove all files and directories under this
            directory.

        Notes
        -----
            This method is not present in the superclass.
        """
        log.debug("remove_dir %s [%d] recursive=%s", self, id(self), recursive)

        if not self.isdir():
            raise NotADirectoryError(f"{self} is not a directory")

        for root, subdirs, files in self.walk():
            if not recursive and (len(subdirs) > 0 or len(files) > 0):
                raise IsADirectoryError(f"Directory at {self} is not empty and recursive argument is False")

            for file in files:
                root.join(file).remove()

            for subdir in subdirs:
                DavResourcePath(root.join(subdir, forceDirectory=True)).remove_dir(recursive=recursive)

        # Remove empty top directory
        self.remove()

    @override
    def transfer_from(
        self,
        src: ResourcePath,
        transfer: str = "copy",
        overwrite: bool = False,
        transaction: TransactionProtocol | None = None,
        multithreaded: bool = True,
    ) -> None:
        """Transfer to this URI from another.

        Parameters
        ----------
        src : `ResourcePath`
            Source URI.
        transfer : `str`
            Mode to use for transferring the resource. Generically there are
            many standard options: copy, link, symlink, hardlink, relsymlink.
            Not all URIs support all modes.
        overwrite : `bool`, optional
            Allow an existing file to be overwritten. Defaults to `False`.
        transaction : `~lsst.resources.utils.TransactionProtocol`, optional
            A transaction object that can (depending on implementation)
            rollback transfers on error.  Not guaranteed to be implemented.
        multithreaded : `bool`, optional
            If `True` the transfer will be allowed to attempt to improve
            throughput by using parallel download streams. This may of no
            effect if the URI scheme does not support parallel streams or
            if a global override has been applied. If `False` parallel
            streams will be disabled.
        """
        log.debug(
            "transfer_from %s [%d] src=%s transfer=%s overwrite=%s",
            self,
            id(self),
            src,
            transfer,
            overwrite,
        )

        # Fail early to prevent delays if remote resources are requested.
        if transfer not in self.transferModes:
            raise ValueError(f"Transfer mode {transfer} not supported by URI scheme {self.scheme}")

        # Existence checks cost time so do not call this unless we know
        # that debugging is enabled.
        destination_exists = None
        if log.isEnabledFor(logging.DEBUG):
            destination_exists = self.exists()
            log.debug(
                "Transferring %s [exists: %s] -> %s [exists: %s] (transfer=%s)",
                redact_url(src.geturl()),
                src.exists(),
                self,
                destination_exists,
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

        if not overwrite:
            if destination_exists is None:
                destination_exists = self.exists()

            if destination_exists:
                raise FileExistsError(f"Destination path {self} already exists.")

        if transfer == "auto":
            transfer = self.transferDefault

        # We can use webDAV 'COPY' or 'MOVE' if both the current and source
        # resources are located in the same server.
        if isinstance(src, type(self)) and self.root_uri() == src.root_uri():
            log.debug("Transfer from %s to %s [%d] directly", src, self, id(self))
            return (
                self._move_from(src, overwrite=overwrite)
                if transfer == "move"
                else self._copy_from(src, overwrite=overwrite)
            )

        # For resources of different classes we can perform the copy or move
        # operation by downloading to a local file and uploading to the
        # destination.
        self._copy_via_local(src)

        # This was an explicit move, try to remove the source.
        if transfer == "move":
            src.remove()

    def _copy_via_local(self, source: ResourcePath) -> None:
        """Replace the contents of this resource with the contents of a remote
        resource by using a local temporary file.

        Parameters
        ----------
        source : `ResourcePath`
            The source of the contents to copy to `self`.
        """
        with source.as_local() as local_uri:
            log.debug(
                "Transfer from %s to %s [%d] via local file %s",
                redact_url(source.geturl()),
                self,
                id(self),
                local_uri,
            )
            with open(local_uri.ospath, "rb") as f:
                self.write(data=f)

    def _copy_from(self, source: DavResourcePath, overwrite: bool = False) -> None:
        """Copy the contents of `source` to this resource. `source` must
        be a file.
        """
        log.debug("_copy_from %s [%d] source=%s overwrite=%s", self, id(self), source, overwrite)

        # Copy is only supported for files, not directories.
        if self.isdir():
            raise ValueError(f"Copy is not supported because destination {self} is a directory")

        if source.isdir():
            raise ValueError(f"Copy is not supported for directory {source}")

        if not source.exists():
            raise FileNotFoundError(f"No file found at {source}")

        self._client.copy(source._internal_url, self._internal_url, overwrite)

    def _move_from(self, source: DavResourcePath, overwrite: bool = False) -> None:
        """Send a MOVE webDAV request to replace the contents of this resource
        with the contents of another resource located in the same server.

        Parameters
        ----------
        source : `DavResourcePath`
            The source of the contents to move to `self`.
        """
        log.debug("_move_from %s [%d] source=%s overwrite=%s", self, id(self), source, overwrite)

        # Move is only supported for files, not directories.
        if self.isdir():
            raise ValueError(f"Move is not supported for destination directory {self}")

        if source.isdir():
            raise ValueError(f"Move is not supported for directory {source}")

        if not source.exists():
            raise FileNotFoundError(f"No file found at {source}")

        self._client.move(source._internal_url, self._internal_url, overwrite)

    @override
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
        if not self.isdir():
            raise ValueError(f"Can not walk non-directory URI {self}")

        # We must return no entries for non-existent directories.
        if not self.exists():
            return

        # Retrieve the entries in this directory
        entries = self._client.read_dir(self._internal_url)
        files = [e.name for e in entries if e.is_file]
        subdirs = [e.name for e in entries if e.is_dir]

        # Filter files
        if isinstance(file_filter, str):
            file_filter = re.compile(file_filter)

        if file_filter is not None:
            files = [f for f in files if file_filter.search(f)]

        if not subdirs and not files:
            return
        else:
            yield type(self)(self, forceAbsolute=False, forceDirectory=True), subdirs, files

        for subdir in subdirs:
            new_uri = self.join(subdir, forceDirectory=True)
            yield from new_uri.walk(file_filter)

    @override
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
        return self._client.generate_presigned_get_url(self._internal_url, expiration_time_seconds)

    @override
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
        return self._client.generate_presigned_put_url(self._internal_url, expiration_time_seconds)

    @override
    def to_fsspec(self) -> tuple[DavFileSystem, str]:
        """Return an abstract file system and path that can be used by fsspec.

        Returns
        -------
        fs : `fsspec.spec.AbstractFileSystem`
            A file system object suitable for use with the returned path.
        path : `str`
            A path that can be opened by the file system object.
        """
        if fsspec is None or not self._client._config.enable_fsspec:
            raise ImportError("fsspec is not available")

        log.debug("DavResourcePath.to_fsspec: %s", self)
        fsys = DavFileSystem(self)
        return fsys, fsys._path

    @override
    @contextlib.contextmanager
    def _openImpl(
        self,
        mode: str = "r",
        *,
        encoding: str | None = None,
    ) -> Iterator[ResourceHandleProtocol]:
        log.debug("DavResourcePath._openImpl: %s mode: %s", self, mode)

        if mode in ("rb", "r") and self._client.accepts_ranges(self._internal_url):
            is_dir, is_file, file_size = self._exists_and_size()
            if is_dir:
                raise OSError(f"open is not implemented for directory {self}")

            if not is_file:
                raise FileNotFoundError(f"No such file {self}")

            with DavReadResourceHandle(mode, log, self, file_size) as handle:
                if mode == "r":
                    # cast because the protocol is compatible, but does not
                    # have BytesIO in the inheritance tree
                    yield io.TextIOWrapper(cast(Any, handle), encoding=encoding)
                else:
                    yield handle
        else:
            with super()._openImpl(mode, encoding=encoding) as handle:
                yield handle


class DavFileSystem(AbstractFileSystem):
    """Minimal fsspec-compatible read-only file system which contains a single
    file.

    Parameters
    ----------
    uri : `DavResourcePath`
        URI of the single resource contained in the file system.
    """

    protocol = ("davs", "dav")

    def __init__(self, uri: DavResourcePath):
        super().__init__()
        self._uri: DavResourcePath = uri
        self._path: str = self._uri.geturl()
        self._size: int | None = None

    @override
    def info(self, path: str, **kwargs: Any) -> dict[str, Any]:
        log.debug("DavFileSystem.info %s", path)
        if path != self._path:
            raise FileNotFoundError(path)

        return {
            "name": path,
            "size": self.size(self._path),
            "type": "file",
        }

    @override
    def ls(self, path: str, detail: bool = True, **kwargs: Any) -> list[str] | list[dict[str, str]]:
        log.debug("DavFileSystem.ls %s", path)
        if path != self._path:
            raise FileNotFoundError(path)

        return list(self.info(path)) if detail else list(path)

    @override
    def modified(self, path: str) -> datetime.datetime:
        log.debug("DavFileSystem.modified %s", path)
        if path != self._path:
            raise FileNotFoundError(path)

        return self._uri._stat().last_modified

    @override
    def size(self, path: str) -> int:
        log.debug("DavFileSystem.size %s", path)
        if path != self._path:
            raise FileNotFoundError(path)

        if self._size is None:
            self._size = self._uri.size()

        return self._size

    @override
    def isfile(self, path: str) -> bool:
        log.debug("DavFileSystem.isfile %s", path)
        return path == self._path

    @override
    def isdir(self, path: str) -> bool:
        log.debug("DavFileSystem.isdir %s", path)
        return False

    @override
    def exists(self, path: str, **kwargs: Any) -> bool:
        log.debug("DavFileSystem.exists %s", path)
        return path == self._path

    @override
    def open(
        self,
        path: str,
        mode: str = "rb",
        encoding: str | None = None,
        block_size: int | None = None,
        cache_options: dict[Any, Any] | None = None,
        compression: str | None = None,
        **kwargs: Any,
    ) -> DavReadResourceHandle | io.TextIOWrapper:
        log.debug(
            "DavFileSystem.open path: %s mode: %s encoding: %s blocksize: %s",
            path,
            mode,
            encoding,
            block_size,
        )
        if path != self._path:
            raise FileNotFoundError(f"File {path} does not exist")

        if mode not in ("rb", "r"):
            raise OSError(f"Opening {path} for writing is not supported")

        handle = DavReadResourceHandle(mode, log, self._uri, self.size(self._path))
        if mode == "rb":
            return handle
        else:
            return io.TextIOWrapper(cast(Any, handle), encoding=encoding)

    @property
    def fsid(self) -> Any:
        return "davs"

    @override
    def mkdir(self, path: str, create_parents: bool = True, **kwargs: Any) -> None:
        raise NotImplementedError

    @override
    def makedirs(self, path: str, exist_ok: bool = False) -> None:
        raise NotImplementedError

    @override
    def rmdir(self, path: str) -> None:
        raise NotImplementedError

    @override
    def walk(
        self,
        path: str,
        maxdepth: int | None = None,
        topdown: bool = True,
        on_error: str = "omit",
        **kwargs: Any,
    ) -> None:
        raise NotImplementedError

    @override
    def find(
        self,
        path: str,
        maxdepth: int | None = None,
        withdirs: bool = False,
        detail: bool = False,
        **kwargs: Any,
    ) -> None:
        raise NotImplementedError

    @override
    def du(
        self,
        path: str,
        total: bool = True,
        maxdepth: int | None = None,
        withdirs: bool = False,
        **kwargs: Any,
    ) -> None:
        raise NotImplementedError

    @override
    def glob(self, path: str, maxdepth: int | None = None, **kwargs: Any) -> None:
        raise NotImplementedError

    @override
    def rm_file(self, path: str) -> None:
        raise NotImplementedError

    @override
    def rm(self, path: str, recursive: bool = False, maxdepth: int | None = None) -> None:
        raise NotImplementedError

    @override
    def touch(self, path: str, truncate: bool = True, **kwargs: Any) -> None:
        raise NotImplementedError

    @override
    def ukey(self, path: str) -> None:
        raise NotImplementedError

    @override
    def created(self, path: str) -> None:
        raise NotImplementedError
