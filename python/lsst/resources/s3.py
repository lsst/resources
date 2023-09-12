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

__all__ = ("S3ResourcePath",)

import contextlib
import io
import logging
import re
import sys
import tempfile
import threading
from collections.abc import Iterable, Iterator
from typing import IO, TYPE_CHECKING, cast

from botocore.exceptions import ClientError
from lsst.utils.timer import time_this

from ._resourceHandles._baseResourceHandle import ResourceHandleProtocol
from ._resourceHandles._s3ResourceHandle import S3ResourceHandle
from ._resourcePath import ResourcePath
from .s3utils import (
    _TooManyRequestsError,
    all_retryable_errors,
    backoff,
    bucketExists,
    getS3Client,
    max_retry_time,
    retryable_io_errors,
    s3CheckFileExists,
)

if TYPE_CHECKING:
    with contextlib.suppress(ImportError):
        import boto3

    from .utils import TransactionProtocol


log = logging.getLogger(__name__)


class ProgressPercentage:
    """Progress bar for S3 file uploads."""

    log_level = logging.DEBUG
    """Default log level to use when issuing a message."""

    def __init__(self, file: ResourcePath, file_for_msg: ResourcePath | None = None, msg: str = ""):
        self._filename = file
        self._file_for_msg = str(file_for_msg) if file_for_msg is not None else str(file)
        self._size = file.size()
        self._seen_so_far = 0
        self._lock = threading.Lock()
        self._msg = msg

    def __call__(self, bytes_amount: int) -> None:
        # To simplify, assume this is hooked up to a single filename
        with self._lock:
            self._seen_so_far += bytes_amount
            percentage = (100 * self._seen_so_far) // self._size
            log.log(
                self.log_level,
                "%s %s %s / %s (%s%%)",
                self._msg,
                self._file_for_msg,
                self._seen_so_far,
                self._size,
                percentage,
            )


def _translate_client_error(err: ClientError) -> None:
    """Translate a ClientError into a specialist error if relevant.

    Parameters
    ----------
    err : `ClientError`
        Exception to translate.

    Raises
    ------
    _TooManyRequestsError
        Raised if the `ClientError` looks like a 429 retry request.
    """
    if "(429)" in str(err):
        # ClientError includes the error code in the message
        # but no direct way to access it without looking inside the
        # response.
        raise _TooManyRequestsError(str(err)) from err
    elif "(404)" in str(err):
        # Some systems can generate this rather than NoSuchKey.
        raise FileNotFoundError("Resource not found: {self}")


class S3ResourcePath(ResourcePath):
    """S3 URI resource path implementation class."""

    @property
    def client(self) -> boto3.client:
        """Client object to address remote resource."""
        # Defer import for circular dependencies
        return getS3Client()

    @classmethod
    def _mexists(cls, uris: Iterable[ResourcePath]) -> dict[ResourcePath, bool]:
        # Force client to be created before creating threads.
        getS3Client()

        return super()._mexists(uris)

    @backoff.on_exception(backoff.expo, retryable_io_errors, max_time=max_retry_time)
    def exists(self) -> bool:
        """Check that the S3 resource exists."""
        if self.is_root:
            # Only check for the bucket since the path is irrelevant
            return bucketExists(self.netloc)
        exists, _ = s3CheckFileExists(self, client=self.client)
        return exists

    @backoff.on_exception(backoff.expo, retryable_io_errors, max_time=max_retry_time)
    def size(self) -> int:
        """Return the size of the resource in bytes."""
        if self.dirLike:
            return 0
        exists, sz = s3CheckFileExists(self, client=self.client)
        if not exists:
            raise FileNotFoundError(f"Resource {self} does not exist")
        return sz

    @backoff.on_exception(backoff.expo, retryable_io_errors, max_time=max_retry_time)
    def remove(self) -> None:
        """Remove the resource."""
        # https://github.com/boto/boto3/issues/507 - there is no
        # way of knowing if the file was actually deleted except
        # for checking all the keys again, reponse is  HTTP 204 OK
        # response all the time
        try:
            self.client.delete_object(Bucket=self.netloc, Key=self.relativeToPathRoot)
        except (self.client.exceptions.NoSuchKey, self.client.exceptions.NoSuchBucket) as err:
            raise FileNotFoundError("No such resource: {self}") from err

    @backoff.on_exception(backoff.expo, all_retryable_errors, max_time=max_retry_time)
    def read(self, size: int = -1) -> bytes:
        """Read the contents of the resource."""
        args = {}
        if size > 0:
            args["Range"] = f"bytes=0-{size-1}"
        try:
            response = self.client.get_object(Bucket=self.netloc, Key=self.relativeToPathRoot, **args)
        except (self.client.exceptions.NoSuchKey, self.client.exceptions.NoSuchBucket) as err:
            raise FileNotFoundError(f"No such resource: {self}") from err
        except ClientError as err:
            _translate_client_error(err)
            raise
        with time_this(log, msg="Read from %s", args=(self,)):
            body = response["Body"].read()
        response["Body"].close()
        return body

    @backoff.on_exception(backoff.expo, all_retryable_errors, max_time=max_retry_time)
    def write(self, data: bytes, overwrite: bool = True) -> None:
        """Write the supplied data to the resource."""
        if not overwrite and self.exists():
            raise FileExistsError(f"Remote resource {self} exists and overwrite has been disabled")
        with time_this(log, msg="Write to %s", args=(self,)):
            self.client.put_object(Bucket=self.netloc, Key=self.relativeToPathRoot, Body=data)

    @backoff.on_exception(backoff.expo, all_retryable_errors, max_time=max_retry_time)
    def mkdir(self) -> None:
        """Write a directory key to S3."""
        if not bucketExists(self.netloc):
            raise ValueError(f"Bucket {self.netloc} does not exist for {self}!")

        if not self.dirLike:
            raise NotADirectoryError(f"Can not create a 'directory' for file-like URI {self}")

        # don't create S3 key when root is at the top-level of an Bucket
        if self.path != "/":
            self.client.put_object(Bucket=self.netloc, Key=self.relativeToPathRoot)

    @backoff.on_exception(backoff.expo, all_retryable_errors, max_time=max_retry_time)
    def _download_file(self, local_file: IO, progress: ProgressPercentage | None) -> None:
        """Download the remote resource to a local file.

        Helper routine for _as_local to allow backoff without regenerating
        the temporary file.
        """
        try:
            self.client.download_fileobj(self.netloc, self.relativeToPathRoot, local_file, Callback=progress)
        except (
            self.client.exceptions.NoSuchKey,
            self.client.exceptions.NoSuchBucket,
        ) as err:
            raise FileNotFoundError(f"No such resource: {self}") from err
        except ClientError as err:
            _translate_client_error(err)
            raise

    def _as_local(self) -> tuple[str, bool]:
        """Download object from S3 and place in temporary directory.

        Returns
        -------
        path : `str`
            Path to local temporary file.
        temporary : `bool`
            Always returns `True`. This is always a temporary file.
        """
        with (
            tempfile.NamedTemporaryFile(suffix=self.getExtension(), delete=False) as tmpFile,
            time_this(log, msg="Downloading %s to local file", args=(self,)),
        ):
            progress = (
                ProgressPercentage(self, msg="Downloading:")
                if log.isEnabledFor(ProgressPercentage.log_level)
                else None
            )
            self._download_file(tmpFile, progress)
        return tmpFile.name, True

    @backoff.on_exception(backoff.expo, all_retryable_errors, max_time=max_retry_time)
    def _upload_file(self, local_file: ResourcePath, progress: ProgressPercentage | None) -> None:
        """Upload a local file with backoff.

        Helper method to wrap file uploading in backoff for transfer_from.
        """
        try:
            self.client.upload_file(
                local_file.ospath, self.netloc, self.relativeToPathRoot, Callback=progress
            )
        except self.client.exceptions.NoSuchBucket as err:
            raise NotADirectoryError(f"Target does not exist: {err}") from err
        except ClientError as err:
            _translate_client_error(err)
            raise

    @backoff.on_exception(backoff.expo, all_retryable_errors, max_time=max_retry_time)
    def _copy_from(self, src: ResourcePath) -> None:
        copy_source = {
            "Bucket": src.netloc,
            "Key": src.relativeToPathRoot,
        }
        try:
            self.client.copy_object(CopySource=copy_source, Bucket=self.netloc, Key=self.relativeToPathRoot)
        except (self.client.exceptions.NoSuchKey, self.client.exceptions.NoSuchBucket) as err:
            raise FileNotFoundError("No such resource to transfer: {self}") from err
        except ClientError as err:
            _translate_client_error(err)
            raise

    def transfer_from(
        self,
        src: ResourcePath,
        transfer: str = "copy",
        overwrite: bool = False,
        transaction: TransactionProtocol | None = None,
    ) -> None:
        """Transfer the current resource to an S3 bucket.

        Parameters
        ----------
        src : `ResourcePath`
            Source URI.
        transfer : `str`
            Mode to use for transferring the resource. Supports the following
            options: copy.
        overwrite : `bool`, optional
            Allow an existing file to be overwritten. Defaults to `False`.
        transaction : `~lsst.resources.utils.TransactionProtocol`, optional
            Currently unused.
        """
        # Fail early to prevent delays if remote resources are requested
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
            # Looks like an S3 remote uri so we can use direct copy
            # note that boto3.resource.meta.copy is cleverer than the low
            # level copy_object
            with time_this(log, msg=timer_msg, args=timer_args):
                self._copy_from(src)

        else:
            # Use local file and upload it
            with src.as_local() as local_uri:
                progress = (
                    ProgressPercentage(local_uri, file_for_msg=src, msg="Uploading:")
                    if log.isEnabledFor(ProgressPercentage.log_level)
                    else None
                )
                with time_this(log, msg=timer_msg, args=timer_args):
                    self._upload_file(local_uri, progress)

        # This was an explicit move requested from a remote resource
        # try to remove that resource
        if transfer == "move":
            # Transactions do not work here
            src.remove()

    @backoff.on_exception(backoff.expo, all_retryable_errors, max_time=max_retry_time)
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
        # We pretend that S3 uses directories and files and not simply keys
        if not (self.isdir() or self.is_root):
            raise ValueError(f"Can not walk a non-directory URI: {self}")

        if isinstance(file_filter, str):
            file_filter = re.compile(file_filter)

        s3_paginator = self.client.get_paginator("list_objects_v2")

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
        dirnames = []
        filenames = []
        files_there = False

        for page in s3_paginator.paginate(Bucket=self.netloc, Prefix=prefix, Delimiter="/"):
            # All results are returned as full key names and we must
            # convert them back to the root form. The prefix is fixed
            # and delimited so that is a simple trim

            # Directories are reported in the CommonPrefixes result
            # which reports the entire key and must be stripped.
            found_dirs = [dir["Prefix"][prefix_len:] for dir in page.get("CommonPrefixes", ())]
            dirnames.extend(found_dirs)

            found_files = [file["Key"][prefix_len:] for file in page.get("Contents", ())]
            if found_files:
                files_there = True
            if file_filter is not None:
                found_files = [f for f in found_files if file_filter.search(f)]

            filenames.extend(found_files)

        # Directories do not exist so we can't test for them. If no files
        # or directories were found though, this means that it effectively
        # does not exist and we should match os.walk() behavior and return
        # immediately.
        if not dirnames and not files_there:
            return
        else:
            yield self, dirnames, filenames

        for dir in dirnames:
            new_uri = self.join(dir)
            yield from new_uri.walk(file_filter)

    @contextlib.contextmanager
    def _openImpl(
        self,
        mode: str = "r",
        *,
        encoding: str | None = None,
    ) -> Iterator[ResourceHandleProtocol]:
        with S3ResourceHandle(mode, log, self.client, self.netloc, self.relativeToPathRoot) as handle:
            if "b" in mode:
                yield handle
            else:
                if encoding is None:
                    encoding = sys.getdefaultencoding()
                # cast because the protocol is compatible, but does not have
                # BytesIO in the inheritance tree
                with io.TextIOWrapper(cast(io.BytesIO, handle), encoding=encoding, write_through=True) as sub:
                    yield sub
