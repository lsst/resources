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

"""Accessing Google Cloud Storage resources."""

from __future__ import annotations

__all__ = ("GSResourcePath",)

import contextlib
import logging
import re
import tempfile
from collections.abc import Iterator
from typing import TYPE_CHECKING

from ._resourceHandles._baseResourceHandle import ResourceHandleProtocol

try:
    import google.api_core.retry as retry
    import google.cloud.storage as storage
    from google.cloud.exceptions import (
        BadGateway,
        InternalServerError,
        NotFound,
        ServiceUnavailable,
        TooManyRequests,
    )
except ImportError:
    storage = None
    retry = None

    # Must also fake the exception classes.
    class ClientError(Exception):
        """Generic client error."""

        pass

    class NotFound(ClientError):  # type: ignore  # noqa: N818
        """Resource not found error."""

        pass

    class TooManyRequests(ClientError):  # type: ignore  # noqa: N818
        """Too many requests error."""

        pass

    class InternalServerError(ClientError):  # type: ignore
        """Internal server error."""

        pass

    class BadGateway(ClientError):  # type: ignore  # noqa: N818
        """Bad gateway error."""

        pass

    class ServiceUnavailable(ClientError):  # type: ignore  # noqa: N818
        """Service unavailable error."""

        pass


from lsst.utils.timer import time_this

from ._resourcePath import ResourcePath

if TYPE_CHECKING:
    from .utils import TransactionProtocol

log = logging.getLogger(__name__)


_RETRIEVABLE_TYPES = (
    TooManyRequests,  # 429
    InternalServerError,  # 500
    BadGateway,  # 502
    ServiceUnavailable,  # 503
)


def is_retryable(exc: Exception) -> bool:
    """Report if the given exception is a condition that can be retried."""
    return isinstance(exc, _RETRIEVABLE_TYPES)


_RETRY_POLICY = retry.Retry(predicate=is_retryable) if retry else None


_client = None
"""Cached client connection."""


def _get_client() -> storage.Client:
    global _client
    if storage is None:
        raise ImportError("google-cloud-storage package not installed. Unable to communicate with GCS.")
    if _client is None:
        _client = storage.Client()
    return _client


class GSResourcePath(ResourcePath):
    """Access Google Cloud Storage resources."""

    _bucket: storage.Bucket | None = None
    _blob: storage.Blob | None = None
    _client: storage.Client | None = None

    @property
    def client(self) -> storage.Client:
        return _get_client()

    @property
    def bucket(self) -> storage.Bucket:
        if self._bucket is None:
            self._bucket = self.client.get_bucket(self.netloc, retry=_RETRY_POLICY)
        return self._bucket

    @property
    def blob(self) -> storage.Blob:
        if self._blob is None:
            self._blob = self.bucket.blob(self.relativeToPathRoot)
        return self._blob

    def exists(self) -> bool:
        if self.is_root:
            return self.bucket.exists(retry=_RETRY_POLICY)
        return self.blob.exists(retry=_RETRY_POLICY)

    def size(self) -> int:
        if self.dirLike:
            return 0
        # The first time this is called we need to sync from the remote.
        # Force the blob to be recalculated.
        try:
            self.blob.reload(retry=_RETRY_POLICY)
        except NotFound:
            raise FileNotFoundError(f"Resource {self} does not exist") from None
        size = self.blob.size
        if size is None:
            raise FileNotFoundError(f"Resource {self} does not exist")
        return size

    def remove(self) -> None:
        try:
            self.blob.delete(retry=_RETRY_POLICY)
        except NotFound as e:
            raise FileNotFoundError(f"No such resource: {self}") from e

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            start = None
            end = None
        else:
            start = 0
            end = size - 1
        try:
            with time_this(log, msg="Read from %s", args=(self,)):
                body = self.blob.download_as_bytes(start=start, end=end, retry=_RETRY_POLICY)
        except NotFound as e:
            raise FileNotFoundError(f"No such resource: {self}") from e
        return body

    def write(self, data: bytes, overwrite: bool = True) -> None:
        if not overwrite and self.exists():
            raise FileExistsError(f"Remote resource {self} exists and overwrite has been disabled")
        with time_this(log, msg="Write to %s", args=(self,)):
            self.blob.upload_from_string(data, retry=_RETRY_POLICY)

    def mkdir(self) -> None:
        if not self.bucket.exists(retry=_RETRY_POLICY):
            raise ValueError(f"Bucket {self.netloc} does not exist for {self}!")

        if not self.dirLike:
            raise NotADirectoryError(f"Can not create a 'directory' for a file-like URI {self}")

        if self.is_root:
            # The root must already exist.
            return

        # Should this method do anything at all?
        self.blob.upload_from_string(b"", retry=_RETRY_POLICY)

    def _as_local(self) -> tuple[str, bool]:
        with (
            tempfile.NamedTemporaryFile(suffix=self.getExtension(), delete=False) as tmpFile,
            time_this(log, msg="Downloading %s to local file", args=(self,)),
        ):
            try:
                self.blob.download_to_file(tmpFile, retry=_RETRY_POLICY)
            except NotFound as e:
                raise FileNotFoundError(f"No such resource: {self}") from e
        return tmpFile.name, True

    def transfer_from(
        self,
        src: ResourcePath,
        transfer: str = "copy",
        overwrite: bool = False,
        transaction: TransactionProtocol | None = None,
    ) -> None:
        if transfer not in self.transferModes:
            raise ValueError(f"Transfer mode '{transfer}' not supported by URI scheme {self.scheme}")

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

        # Short circuit if the URIs are identical immediately.
        if self == src:
            log.debug(
                "Target and destination URIs are identical: %s, returning immediately."
                " No further action required.",
                self,
            )
            return

        if not overwrite and self.exists():
            raise FileExistsError(f"Destination path '{self}' already exists.")

        if transfer == "auto":
            transfer = self.transferDefault

        timer_msg = "Transfer from %s to %s"
        timer_args = (src, self)

        if isinstance(src, type(self)):
            # Looks like a GS remote uri so we can use direct copy
            with time_this(log, msg=timer_msg, args=timer_args):
                rewrite_token = None
                while True:
                    try:
                        rewrite_token, bytes_copied, total_bytes = self.blob.rewrite(
                            src.blob, token=rewrite_token, retry=_RETRY_POLICY
                        )
                    except NotFound as e:
                        raise FileNotFoundError("No such resource to transfer: {self}") from e
                    log.debug("Copied %d bytes out of %d (%s to %s)", bytes_copied, total_bytes, src, self)
                    if rewrite_token is None:
                        # Copy has completed
                        break
        else:
            # Use local file and upload it
            with src.as_local() as local_uri, time_this(log, msg=timer_msg, args=timer_args):
                self.blob.upload_from_filename(local_uri.ospath, retry=_RETRY_POLICY)

        # This was an explicit move requested from a remote resource
        # try to remove that resource
        if transfer == "move":
            # Transactions do not work here
            src.remove()

    @contextlib.contextmanager
    def open(
        self,
        mode: str = "r",
        *,
        encoding: str | None = None,
        prefer_file_temporary: bool = False,
    ) -> Iterator[ResourceHandleProtocol]:
        # Docstring inherited
        if self.isdir() or self.is_root:
            raise IsADirectoryError(f"Can not 'open' a directory URI: {self}")
        if "x" in mode:
            if self.exists():
                raise FileExistsError(f"File at {self} already exists.")
            mode = mode.replace("x", "w")

        # Clear the blob before calling open if we are in write mode.
        # This ensures that everything is resynced.
        if "w" in mode:
            self._blob = None

        # The GCS API does not support append or read/write modes so for
        # those we use the base class implementation.
        # There seems to be a bug in the Google open() API where it does not
        # properly write a BOM at the start of the file in UTF-16 encoding
        # which leads to python not being able to read the contents back.
        if "+" in mode or "a" in mode or ("w" in mode and encoding == "utf-16"):
            with super().open(mode, encoding=encoding, prefer_file_temporary=prefer_file_temporary) as buffer:
                yield buffer
        else:
            with self.blob.open(mode, encoding=encoding, retry=_RETRY_POLICY) as buffer:
                yield buffer

    def walk(
        self, file_filter: str | re.Pattern | None = None
    ) -> Iterator[list | tuple[ResourcePath, list[str], list[str]]]:
        # We pretend that GCS uses directories and files and not simply keys.
        if not (self.isdir() or self.is_root):
            raise ValueError(f"Can not walk a non-directory URI: {self}")

        if isinstance(file_filter, str):
            file_filter = re.compile(file_filter)

        # Limit each query to a single "directory" to match os.walk
        # We could download all keys at once with no delimiter and work
        # it out locally but this could potentially lead to large memory
        # usage for millions of keys. It will also make the initial call
        # to this method potentially very slow. If making this method look
        # like os.walk was not required, we could query all keys with
        # pagination and return them in groups of 1000, but that would
        # be a different interface since we can't guarantee we would get
        # them all grouped properly across the 1000 limit boundary.
        prefix = self.relativeToPathRoot if not self.is_root else ""
        prefix_len = len(prefix)
        dirnames: set[str] = set()
        filenames = []
        files_there = False

        blobs = self.client.list_blobs(self.bucket, prefix=prefix, delimiter="/", retry=_RETRY_POLICY)
        for page in blobs.pages:
            # "Sub-directories" turn up as prefixes in each page.
            dirnames.update(dir[prefix_len:] for dir in page.prefixes)

            # Files are reported for this "directory" only.
            # The prefix itself can be included as a file because we write
            # a zero-length file for mkdir(). These must be filtered out.
            found_files = [f.name[prefix_len:] for f in page if f.name != prefix]
            if file_filter is not None:
                found_files = [f for f in found_files if file_filter.search(f)]
            if found_files:
                files_there = True

            filenames.extend(found_files)

        if not dirnames and not files_there:
            # Nothing found so match os.walk and return immediately.
            return
        else:
            yield self, sorted(dirnames), filenames

        for dir in sorted(dirnames):
            new_uri = self.join(dir)
            yield from new_uri.walk(file_filter)
