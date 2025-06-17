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
from typing import TYPE_CHECKING, Any, BinaryIO, cast

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
        # `DavResourcePath`must use and its associated buffer size (in bytes).
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

        # Cached attributes of this file
        self._cached_metadata: DavFileMetadata | None = None

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

    def _stat(self, refresh: bool = False) -> DavFileMetadata:
        """Retrieve metadata about this resource.

        We cache this resource's metadata to avoid expensive roundtrips to
        the server for each call.

        Parameters
        ----------
        refresh : `bool`, optional
            If True, metadata is retrieved again from the server even if it
            is already cached.

        Notes
        -----
        Cached metadata is explicitly invalidated when this resource is
        modified, for instance as a result of calling write(), transfer_from()
        remove(), etc.
        """
        # Caching metadata is a compromise because each roundtrip is
        # relatively expensive and is fragile if this same resource is
        # modified by a different thread or by a different process.
        if refresh or self._cached_metadata is None:
            self._cached_metadata = self._client.stat(self._internal_url)

        return self._cached_metadata

    def _invalidate_metatada_cache(self) -> None:
        """Invalidate cached metadata for this resource.

        This method is intended to be explicitly invoked when a method
        modifies the content of this resource (e.g. write, remove,
        transfer_from).
        """
        self._cached_metadata = None

    def mkdir(self) -> None:
        """Create the directory resource if it does not already exist."""
        if not self.isdir():
            raise NotADirectoryError(f"Can not create a directory for file-like URI {self}")

        stat = self._stat()
        if stat.is_dir:
            return

        if stat.is_file:
            # A file exists at this path.
            raise NotADirectoryError(
                f"Can not create a directory for {self} because a file already exists at that URL"
            )

        # Target directory does not exist. Create it and its ancestors as
        # needed. We need to test if parent URL is different from self URL,
        # otherwise we could be stuck in a recursive loop
        # where self == parent.
        if self.geturl() != self.parent().geturl():
            self.parent().mkdir()

        self._client.mkcol(self._internal_url)
        self._invalidate_metatada_cache()

    def exists(self) -> bool:
        """Check that this resource exists."""
        # Force checking for existence against the server for all the
        # external calls to this method.
        return self._stat(refresh=True).exists

    def size(self) -> int:
        """Return the size of the remote resource in bytes."""
        if self.isdir():
            return 0

        stat = self._stat()
        if not stat.exists:
            raise FileNotFoundError(f"No file or directory found at {self}")

        return stat.size

    def info(self) -> dict[str, Any]:
        """Return metadata details about this resource."""
        return self._client.info(self._internal_url, name=str(self))

    def read(self, size: int = -1) -> bytes:
        """Open the resource and return the contents in bytes.

        Parameters
        ----------
        size : `int`, optional
            The number of bytes to read. Negative or omitted indicates that
            all data should be read.
        """
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

        stat = self._stat()
        if stat.is_dir:
            raise ValueError(f"method read() is not implemented for directory {self}")
        elif not stat.exists:
            raise FileNotFoundError(f"no file found at {self}")
        elif stat.size == 0:
            # This is an empty file.
            return b""

        if size > 0:
            end_range = min(stat.size, size) - 1
            return self._client.read_range(self._internal_url, start=0, end=end_range)
        else:
            return self._client.read(self._internal_url)

    def read_range(
        self,
        start: int,
        end: int | None = None,
        check_exists: bool = False,
        headers: dict[str, str] | None = None,
    ) -> bytes:
        """Read the specified range of the resource and return the bytes read.

        Parameters
        ----------
        start : `int`
            Position of the first byte to read.
        end : `int`, optional
            Position of the last byte to read.
        check_exists : `bool`, optional
            Check the file exists before sending the GET request, which may
            fail if the file does not exist. This is useful when the caller
            has already checked the file exists before doing several
            partial reads, so we want to avoid checking for every call.
        headers : `dict[str, str]`, optional
            Headers to include in the partial GET request.
        """
        if check_exists:
            stat = self._stat()
            if not stat.is_file:
                raise FileNotFoundError(f"No file found at {self}")

            if stat.size == 0:
                # This is an empty file.
                return b""

        headers = {} if headers is None else dict(headers)
        headers.update({"Accept-Encoding": "identity"})
        return self._client.read_range(self._internal_url, start=start, end=end, headers=headers)

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
        # We need to ensure that this resource is actually a file. dCache
        # responds with a HTML-formatted content to a HTTP GET request to a
        # directory, which is not what we want.
        stat = self._stat()
        if not stat.is_file:
            raise FileNotFoundError(f"No file found at {self}")

        if tmpdir is None:
            local_dir, buffer_size = self._config.tmpdir_buffersize
            tmpdir = ResourcePath(local_dir, forceDirectory=True)
        else:
            buffer_size = _calc_tmpdir_buffer_size(tmpdir.ospath)

        with ResourcePath.temporary_uri(suffix=self.getExtension(), prefix=tmpdir, delete=True) as tmp_uri:
            self._client.download(self._internal_url, tmp_uri.ospath, buffer_size)
            yield tmp_uri

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
        if self.isdir():
            raise ValueError(f"Method write() is not implemented for directory {self}")

        stat = self._stat()
        if stat.is_file and not overwrite:
            raise FileExistsError(f"File {self} exists and overwrite has been disabled")

        # Create parent directory and upload the data.
        self.parent().mkdir()
        self._client.write(self._internal_url, data)
        self._invalidate_metatada_cache()

    def remove(self) -> None:
        """Remove the resource.

        If the resource is a directory, it must be empty otherwise this
        method raises. Removing a non-existent file or directory is not
        considered an error.
        """
        if not self.exists():
            return

        if self.isdir():
            entries = self._client.read_dir(self._internal_url)
            if len(entries) > 0:
                raise IsADirectoryError(f"directory {self} is not empty")

        # This resource is a either file or an empty directory, we can remove
        # it.
        self._client.delete(self._internal_url)
        self._invalidate_metatada_cache()

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
        if not self.isdir():
            raise NotADirectoryError(f"{self} is not a directory")

        for root, subdirs, files in self.walk():
            if not recursive and (len(subdirs) > 0 or len(files) > 0):
                raise IsADirectoryError(f"directory {self} is not empty and recursive argument is False")

            for file in files:
                root.join(file).remove()

            for subdir in subdirs:
                DavResourcePath(root.join(subdir, forceDirectory=True)).remove_dir(recursive=recursive)

        # Remove empty top directory
        self.remove()

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
        # Fail early to prevent delays if remote resources are requested.
        if transfer not in self.transferModes:
            raise ValueError(f"Transfer mode {transfer} not supported by URI scheme {self.scheme}")

        # Existence checks cost time so do not call this unless we know
        # that debugging is enabled.
        destination_exists = self.exists()
        if log.isEnabledFor(logging.DEBUG):
            log.debug(
                "Transferring %s [exists: %s] -> %s [exists: %s] (transfer=%s)",
                src,
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

        if not overwrite and destination_exists:
            raise FileExistsError(f"Destination path {self} already exists.")

        if transfer == "auto":
            transfer = self.transferDefault

        # We can use webDAV 'COPY' or 'MOVE' if both the current and source
        # resources are located in the same server.
        if isinstance(src, type(self)) and self.root_uri() == src.root_uri():
            log.debug("Transfer from %s to %s directly", src, self)
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
            log.debug("Transfer from %s to %s via local file %s", source, self, local_uri)
            with open(local_uri.ospath, "rb") as f:
                self.write(data=f)

        self._invalidate_metatada_cache()

    def _copy_from(self, source: DavResourcePath, overwrite: bool = False) -> None:
        """Copy the contents of `source` to this resource. `source` must
        be a file.
        """
        # Copy is only supported for files, not directories.
        if source.isdir():
            raise ValueError(f"Copy is not supported for directory {source}")

        src_stat = source._stat()
        if not src_stat.is_file:
            raise FileNotFoundError(f"No such file {source}")

        dst_stat = self._stat()
        if dst_stat.is_dir:
            raise ValueError(f"Copy is not supported because destination {self} is a directory")

        self.parent().mkdir()
        self._client.copy(source._internal_url, self._internal_url, overwrite)
        self._invalidate_metatada_cache()

    def _move_from(self, source: DavResourcePath, overwrite: bool = False) -> None:
        """Send a MOVE webDAV request to replace the contents of this resource
        with the contents of another resource located in the same server.

        Parameters
        ----------
        source : `DavResourcePath`
            The source of the contents to move to `self`.
        """
        # Move is only supported for files, not directories.
        if source.isdir():
            raise ValueError(f"Move is not supported for directory {source}")

        src_stat = source._stat()
        if not src_stat.is_file:
            raise FileNotFoundError(f"No such file {source}")

        dst_stat = self._stat()
        if dst_stat.is_dir:
            raise ValueError(f"Move is not supported for destination directory {self}")

        # Create the destination's parent directory, move the source to
        # this resource and invalidate caches for both.
        self.parent().mkdir()
        self._client.move(source._internal_url, self._internal_url, overwrite)
        self._invalidate_metatada_cache()
        source._invalidate_metatada_cache()

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
            raise ValueError("Can not walk a non-directory URI")

        # We must return no entries for non-existent directories.
        if not self._stat().exists:
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

        path: str = self.path
        return DavFileSystem(self, path), path

    @contextlib.contextmanager
    def _openImpl(
        self,
        mode: str = "r",
        *,
        encoding: str | None = None,
    ) -> Iterator[ResourceHandleProtocol]:
        if self.isdir():
            raise OSError(f"open is not implemented for directory {self}")

        if mode in ("rb", "r") and self._client.accepts_ranges(self._internal_url):
            stat: DavFileMetadata = self._stat(refresh=True)
            if not stat.exists:
                raise FileNotFoundError(f"No such file {self}")

            if not stat.is_file:
                raise OSError(f"open is not implemented for directory {self}")

            handle: ResourceHandleProtocol = DavReadResourceHandle(mode, log, self, stat)
            if mode == "r":
                # cast because the protocol is compatible, but does not have
                # BytesIO in the inheritance tree
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

    path : `str`
        Path within the file system of the file.
    """

    def __init__(self, uri: DavResourcePath, path: str):
        self._uri: DavResourcePath = uri
        self._path: str = path

    def info(self, path: str, **kwargs: Any) -> dict[str, Any]:
        if path != self._path:
            raise FileNotFoundError(path)

        return {
            "name": path,
            "size": self._uri.size(),
            "type": "file",
        }

    def ls(self, path: str, detail: bool = True, **kwargs: Any) -> list[str] | list[dict[str, str]]:
        if path != self._path:
            raise FileNotFoundError(path)

        return list(self.info(path)) if detail else list(path)

    def modified(self, path: str) -> datetime.datetime:
        if path != self._path:
            raise FileNotFoundError(path)

        return self._uri._stat().last_modified

    def size(self, path: str) -> int:
        if path != self._path:
            raise FileNotFoundError(path)

        return self._uri.size()

    def isfile(self, path: str) -> bool:
        return path == self._path

    def isdir(self, path: str) -> bool:
        return False

    def exists(self, path: str, **kwargs: Any) -> bool:
        return path == self._path

    def open(
        self,
        path: str,
        mode: str = "rb",
        encoding: str | None = None,
        block_size: int | None = None,
        cache_options: dict[Any, Any] | None = None,
        compression: str | None = None,
        **kwargs: Any,
    ) -> ResourceHandleProtocol[Any]:
        if path != self._path:
            raise FileNotFoundError(path)

        with self._uri.open(mode=mode, encoding=encoding) as handle:
            return handle

    @property
    def fsid(self) -> Any:
        raise NotImplementedError

    def mkdir(self, path: str, create_parents: bool = True, **kwargs: Any) -> None:
        raise NotImplementedError

    def makedirs(self, path: str, exist_ok: bool = False) -> None:
        raise NotImplementedError

    def rmdir(self, path: str) -> None:
        raise NotImplementedError

    def walk(
        self,
        path: str,
        maxdepth: int | None = None,
        topdown: bool = True,
        on_error: str = "omit",
        **kwargs: Any,
    ) -> None:
        raise NotImplementedError

    def find(
        self,
        path: str,
        maxdepth: int | None = None,
        withdirs: bool = False,
        detail: bool = False,
        **kwargs: Any,
    ) -> None:
        raise NotImplementedError

    def du(
        self,
        path: str,
        total: bool = True,
        maxdepth: int | None = None,
        withdirs: bool = False,
        **kwargs: Any,
    ) -> None:
        raise NotImplementedError

    def glob(self, path: str, maxdepth: int | None = None, **kwargs: Any) -> None:
        raise NotImplementedError

    def rm_file(self, path: str) -> None:
        raise NotImplementedError

    def rm(self, path: str, recursive: bool = False, maxdepth: int | None = None) -> None:
        raise NotImplementedError

    def touch(self, path: str, truncate: bool = True, **kwargs: Any) -> None:
        raise NotImplementedError

    def ukey(self, path: str) -> None:
        raise NotImplementedError

    def created(self, path: str) -> None:
        raise NotImplementedError
