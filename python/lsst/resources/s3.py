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

import concurrent.futures
import contextlib
import io
import logging
import os
import re
import sys
import threading
from collections import defaultdict
from collections.abc import Iterable, Iterator
from functools import cache, cached_property
from typing import IO, TYPE_CHECKING, cast

from botocore.exceptions import ClientError

from lsst.utils.iteration import chunk_iterable
from lsst.utils.timer import time_this

from ._resourceHandles._baseResourceHandle import ResourceHandleProtocol
from ._resourceHandles._s3ResourceHandle import S3ResourceHandle
from ._resourcePath import _EXECUTOR_TYPE, MBulkResult, ResourcePath, _get_executor_class, _patch_environ
from .s3utils import (
    _get_s3_connection_parameters,
    _s3_disable_bucket_validation,
    _s3_should_validate_bucket,
    all_retryable_errors,
    backoff,
    bucketExists,
    getS3Client,
    max_retry_time,
    retryable_io_errors,
    s3CheckFileExists,
    translate_client_error,
)
from .utils import _get_num_workers

try:
    from boto3.s3.transfer import TransferConfig  # type: ignore
except ImportError:
    TransferConfig = None

try:
    import s3fs
    from fsspec.spec import AbstractFileSystem
except ImportError:
    s3fs = None
    AbstractFileSystem = type

if TYPE_CHECKING:
    with contextlib.suppress(ImportError):
        import boto3

    from .utils import TransactionProtocol


log = logging.getLogger(__name__)


class ProgressPercentage:
    """Progress bar for S3 file uploads.

    Parameters
    ----------
    file : `ResourcePath`
        Resource that is relevant to the progress percentage. The size of this
        resource will be used to determine progress. The name will be used
        in the log messages unless overridden by ``file_for_msg``.
    file_for_msg : `ResourcePath` or `None`, optional
        Resource name to include in log messages in preference to ``file``.
    msg : `str`, optional
        Message text to be included in every progress log message.
    """

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


@cache
def _parse_string_to_maybe_bool(maybe_bool_str: str) -> bool | None:
    """Map a string to either a boolean value or None.

    Parameters
    ----------
    maybe_bool_str : `str`
        The value to parse

    Results
    -------
    maybe_bool : `bool` or `None`
        The parsed value.
    """
    if maybe_bool_str.lower() in ["t", "true", "yes", "y", "1"]:
        maybe_bool = True
    elif maybe_bool_str.lower() in ["f", "false", "no", "n", "0"]:
        maybe_bool = False
    elif maybe_bool_str.lower() in ["none", ""]:
        maybe_bool = None
    else:
        raise ValueError(f'Value of "{maybe_bool_str}" is not True, False, or None.')

    return maybe_bool


class S3ResourcePath(ResourcePath):
    """S3 URI resource path implementation class.

    Notes
    -----
    In order to configure the behavior of instances of this class, the
    environment variable is inspected:

    - LSST_S3_USE_THREADS: May be True, False, or None. Sets whether threading
    is used for downloads, with a value of None defaulting to boto's default
    value. Users may wish to set it to False when the downloads will be started
    within threads other than python's main thread.
    """

    use_threads: bool | None = None
    """Explicitly turn on or off threading in use of boto's download_fileobj.
    Setting this to None results in boto's default behavior."""

    @cached_property
    def _environ_use_threads(self) -> bool | None:
        try:
            use_threads_str = os.environ["LSST_S3_USE_THREADS"]
        except KeyError:
            use_threads_str = "None"

        use_threads = _parse_string_to_maybe_bool(use_threads_str)

        return use_threads

    @contextlib.contextmanager
    def _use_threads_temp_override(self, multithreaded: bool) -> Iterator:
        """Temporarily override the value of use_threads."""
        original = self.use_threads
        self.use_threads = multithreaded
        yield
        self.use_threads = original

    @property
    def _transfer_config(self) -> TransferConfig:
        if self.use_threads is None:
            self.use_threads = self._environ_use_threads

        if self.use_threads is None:
            transfer_config = TransferConfig()
        else:
            transfer_config = TransferConfig(use_threads=self.use_threads)

        return transfer_config

    @property
    def client(self) -> boto3.client:
        """Client object to address remote resource."""
        return getS3Client(self._profile)

    @property
    def _profile(self) -> str | None:
        """Profile name to use for looking up S3 credentials and endpoint."""
        return self._uri.username

    @property
    def _bucket(self) -> str:
        """S3 bucket where the files are stored."""
        # Notionally the bucket is stored in the 'hostname' part of the URI.
        # However, Ceph S3 uses a "multi-tenant" syntax for bucket names in the
        # form 'tenant:bucket'.  The part after the colon is parsed as the port
        # portion of the URI, and urllib throws an exception if you try to read
        # a non-integer port value.  So manually split off this portion of the
        # URI.
        split = self._uri.netloc.split("@")
        num_components = len(split)
        if num_components == 2:
            # There is a profile@ portion of the URL, so take the second half.
            bucket = split[1]
        elif num_components == 1:
            # There is no profile@, so take the whole netloc.
            bucket = split[0]
        else:
            raise ValueError(f"Unexpected extra '@' in S3 URI: '{str(self)}'")

        if not bucket:
            raise ValueError(f"S3 URI does not include bucket name: '{str(self)}'")

        return bucket

    @classmethod
    def _mexists(
        cls, uris: Iterable[ResourcePath], *, num_workers: int | None = None
    ) -> dict[ResourcePath, bool]:
        # Force client to be created for each profile before creating threads.
        profiles = set[str | None]()
        for path in uris:
            if path.scheme == "s3":
                path = cast(S3ResourcePath, path)
                profiles.add(path._profile)
        for profile in profiles:
            getS3Client(profile)

        return super()._mexists(uris, num_workers=num_workers)

    @classmethod
    def _mremove(cls, uris: Iterable[ResourcePath]) -> dict[ResourcePath, MBulkResult]:
        # Delete multiple objects in one API call.
        # Must group by profile and bucket.
        grouped_uris: dict[tuple[str | None, str], list[S3ResourcePath]] = defaultdict(list)
        for uri in uris:
            uri = cast(S3ResourcePath, uri)
            grouped_uris[uri._profile, uri._bucket].append(uri)

        results: dict[ResourcePath, MBulkResult] = {}
        for related_uris in grouped_uris.values():
            # API requires no more than 1000 per call.
            chunk_num = 0
            chunks: list[tuple[ResourcePath, ...]] = []
            key_to_uri: dict[str, ResourcePath] = {}
            for chunk in chunk_iterable(related_uris, chunk_size=1_000):
                for uri in chunk:
                    key = uri.relativeToPathRoot
                    key_to_uri[key] = uri
                    # Default to assuming everything worked.
                    results[uri] = MBulkResult(True, None)
                chunk_num += 1
                chunks.append(chunk)

            # Bulk remove.
            with time_this(
                log,
                msg="Bulk delete; %d chunk%s; totalling %d dataset%s",
                args=(
                    len(chunks),
                    "s" if len(chunks) != 1 else "",
                    len(related_uris),
                    "s" if len(related_uris) != 1 else "",
                ),
            ):
                errored = cls._mremove_select(chunks)

            # Update with error information.
            results.update(errored)

        return results

    @classmethod
    def _mremove_select(cls, chunks: list[tuple[ResourcePath, ...]]) -> dict[ResourcePath, MBulkResult]:
        if len(chunks) == 1:
            # Do the removal directly without futures.
            return cls._delete_objects_wrapper(chunks[0])
        pool_executor_class = _get_executor_class()
        if issubclass(pool_executor_class, concurrent.futures.ProcessPoolExecutor):
            # Patch the environment to make it think there is only one worker
            # for each subprocess.
            with _patch_environ({"LSST_RESOURCES_NUM_WORKERS": "1"}):
                return cls._mremove_with_pool(pool_executor_class, chunks)
        else:
            return cls._mremove_with_pool(pool_executor_class, chunks)

    @classmethod
    def _mremove_with_pool(
        cls,
        pool_executor_class: _EXECUTOR_TYPE,
        chunks: list[tuple[ResourcePath, ...]],
        *,
        num_workers: int | None = None,
    ) -> dict[ResourcePath, MBulkResult]:
        # Different name because different API to base class.
        # No need to make more workers than we have chunks.
        max_workers = num_workers if num_workers is not None else min(len(chunks), _get_num_workers())
        results: dict[ResourcePath, MBulkResult] = {}
        with pool_executor_class(max_workers=max_workers) as remove_executor:
            future_remove = {
                remove_executor.submit(cls._delete_objects_wrapper, chunk): i
                for i, chunk in enumerate(chunks)
            }
            for future in concurrent.futures.as_completed(future_remove):
                try:
                    results.update(future.result())
                except Exception as e:
                    # The chunk utterly failed.
                    chunk = chunks[future_remove[future]]
                    for uri in chunk:
                        results[uri] = MBulkResult(False, e)
        return results

    @classmethod
    def _delete_objects_wrapper(cls, uris: tuple[ResourcePath, ...]) -> dict[ResourcePath, MBulkResult]:
        """Convert URIs to keys and call low-level API."""
        if not uris:
            return {}
        keys: list[dict[str, str]] = []
        key_to_uri: dict[str, ResourcePath] = {}
        for uri in uris:
            key = uri.relativeToPathRoot
            key_to_uri[key] = uri
            keys.append({"Key": key})

        first_uri = cast(S3ResourcePath, uris[0])
        results = cls._delete_related_objects(first_uri.client, first_uri._bucket, keys)

        # Remap error object keys to uris.
        return {key_to_uri[key]: result for key, result in results.items()}

    @classmethod
    @backoff.on_exception(backoff.expo, retryable_io_errors, max_time=max_retry_time)
    def _delete_related_objects(
        cls, client: boto3.client, bucket: str, keys: list[dict[str, str]]
    ) -> dict[str, MBulkResult]:
        # Delete multiple objects from the same bucket, allowing for backoff
        # retry.
        response = client.delete_objects(Bucket=bucket, Delete={"Objects": keys, "Quiet": True})
        # Use Quiet mode so we assume everything worked unless told otherwise.
        # Only returning errors -- indexed by Key name.
        errors: dict[str, MBulkResult] = {}
        for errored_key in response.get("Errors", []):
            errors[errored_key["Key"]] = MBulkResult(
                False, ClientError({"Error": errored_key}, f"delete_objects: {errored_key['Key']}")
            )
        return errors

    @backoff.on_exception(backoff.expo, retryable_io_errors, max_time=max_retry_time)
    def exists(self) -> bool:
        """Check that the S3 resource exists."""
        if self.is_root:
            # Only check for the bucket since the path is irrelevant
            return bucketExists(self._bucket, self.client)
        exists, _ = s3CheckFileExists(self, bucket=self._bucket, client=self.client)
        return exists

    @backoff.on_exception(backoff.expo, retryable_io_errors, max_time=max_retry_time)
    def size(self) -> int:
        """Return the size of the resource in bytes."""
        if self.dirLike:
            return 0
        exists, sz = s3CheckFileExists(self, bucket=self._bucket, client=self.client)
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
            self.client.delete_object(Bucket=self._bucket, Key=self.relativeToPathRoot)
        except (self.client.exceptions.NoSuchKey, self.client.exceptions.NoSuchBucket) as err:
            raise FileNotFoundError("No such resource: {self}") from err

    @backoff.on_exception(backoff.expo, all_retryable_errors, max_time=max_retry_time)
    def read(self, size: int = -1) -> bytes:
        args = {}
        if size > 0:
            args["Range"] = f"bytes=0-{size - 1}"
        try:
            response = self.client.get_object(Bucket=self._bucket, Key=self.relativeToPathRoot, **args)
        except (self.client.exceptions.NoSuchKey, self.client.exceptions.NoSuchBucket) as err:
            raise FileNotFoundError(f"No such resource: {self}") from err
        except ClientError as err:
            translate_client_error(err, self)
            raise
        with time_this(log, msg="Read from %s", args=(self,)):
            body = response["Body"].read()
        response["Body"].close()
        return body

    @backoff.on_exception(backoff.expo, all_retryable_errors, max_time=max_retry_time)
    def write(self, data: bytes, overwrite: bool = True) -> None:
        if not overwrite and self.exists():
            raise FileExistsError(f"Remote resource {self} exists and overwrite has been disabled")
        with time_this(log, msg="Write to %s", args=(self,)):
            self.client.put_object(Bucket=self._bucket, Key=self.relativeToPathRoot, Body=data)

    @backoff.on_exception(backoff.expo, all_retryable_errors, max_time=max_retry_time)
    def mkdir(self) -> None:
        """Write a directory key to S3."""
        if not bucketExists(self._bucket, self.client):
            raise ValueError(f"Bucket {self._bucket} does not exist for {self}!")

        if not self.dirLike:
            raise NotADirectoryError(f"Can not create a 'directory' for file-like URI {self}")

        # don't create S3 key when root is at the top-level of an Bucket
        if self.path != "/":
            self.client.put_object(Bucket=self._bucket, Key=self.relativeToPathRoot)

    @backoff.on_exception(backoff.expo, all_retryable_errors, max_time=max_retry_time)
    def _download_file(
        self, local_file: IO | ResourceHandleProtocol, progress: ProgressPercentage | None
    ) -> None:
        """Download the remote resource to a local file.

        Helper routine for _as_local to allow backoff without regenerating
        the temporary file.
        """
        try:
            self.client.download_fileobj(
                self._bucket,
                self.relativeToPathRoot,
                local_file,
                Callback=progress,
                Config=self._transfer_config,
            )
        except (
            self.client.exceptions.NoSuchKey,
            self.client.exceptions.NoSuchBucket,
        ) as err:
            raise FileNotFoundError(f"No such resource: {self}") from err
        except ClientError as err:
            translate_client_error(err, self)
            raise

    def to_fsspec(self) -> tuple[AbstractFileSystem, str]:
        """Return an abstract file system and path that can be used by fsspec.

        Returns
        -------
        fs : `fsspec.spec.AbstractFileSystem`
            A file system object suitable for use with the returned path.
        path : `str`
            A path that can be opened by the file system object.
        """
        if s3fs is None:
            raise ImportError("s3fs is not available")
        # Must remove the profile from the URL and form it again.
        endpoint_config = _get_s3_connection_parameters(self._profile)
        s3 = s3fs.S3FileSystem(
            profile=endpoint_config.profile,
            endpoint_url=endpoint_config.endpoint_url,
            key=endpoint_config.access_key_id,
            secret=endpoint_config.secret_access_key,
        )
        if not _s3_should_validate_bucket():
            # Accessing the s3 property forces the boto client to be
            # constructed and cached and allows the validation to be removed.
            _s3_disable_bucket_validation(s3.s3)

        return s3, f"{self._bucket}/{self.relativeToPathRoot}"

    @contextlib.contextmanager
    def _as_local(
        self, multithreaded: bool = True, tmpdir: ResourcePath | None = None
    ) -> Iterator[ResourcePath]:
        """Download object from S3 and place in temporary directory.

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
        with (
            ResourcePath.temporary_uri(prefix=tmpdir, suffix=self.getExtension(), delete=True) as tmp_uri,
            self._use_threads_temp_override(multithreaded),
            time_this(log, msg="Downloading %s to local file", args=(self,)),
        ):
            progress = (
                ProgressPercentage(self, msg="Downloading:")
                if log.isEnabledFor(ProgressPercentage.log_level)
                else None
            )
            with tmp_uri.open("wb") as tmpFile:
                self._download_file(tmpFile, progress)
            yield tmp_uri

    @backoff.on_exception(backoff.expo, all_retryable_errors, max_time=max_retry_time)
    def _upload_file(self, local_file: ResourcePath, progress: ProgressPercentage | None) -> None:
        """Upload a local file with backoff.

        Helper method to wrap file uploading in backoff for transfer_from.
        """
        try:
            self.client.upload_file(
                local_file.ospath,
                self._bucket,
                self.relativeToPathRoot,
                Callback=progress,
                Config=self._transfer_config,
            )
        except self.client.exceptions.NoSuchBucket as err:
            raise NotADirectoryError(f"Target does not exist: {err}") from err
        except ClientError as err:
            translate_client_error(err, self)
            raise

    @backoff.on_exception(backoff.expo, all_retryable_errors, max_time=max_retry_time)
    def _copy_from(self, src: S3ResourcePath) -> None:
        copy_source = {
            "Bucket": src._bucket,
            "Key": src.relativeToPathRoot,
        }
        try:
            self.client.copy_object(CopySource=copy_source, Bucket=self._bucket, Key=self.relativeToPathRoot)
        except (self.client.exceptions.NoSuchKey, self.client.exceptions.NoSuchBucket) as err:
            raise FileNotFoundError(f"No such resource to transfer: {src} -> {self}") from err
        except ClientError as err:
            translate_client_error(err, self)
            raise

    def transfer_from(
        self,
        src: ResourcePath,
        transfer: str = "copy",
        overwrite: bool = False,
        transaction: TransactionProtocol | None = None,
        multithreaded: bool = True,
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
        multithreaded : `bool`, optional
            If `True` the transfer will be allowed to attempt to improve
            throughput by using parallel download streams. This may of no
            effect if the URI scheme does not support parallel streams or
            if a global override has been applied. If `False` parallel
            streams will be disabled.
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

        if isinstance(src, type(self)) and self.client == src.client:
            # Looks like an S3 remote uri so we can use direct copy.
            # This only works if the source and destination are using the same
            # S3 endpoint and profile.
            with time_this(log, msg=timer_msg, args=timer_args):
                self._copy_from(src)

        else:
            # Use local file and upload it
            with src.as_local(multithreaded=multithreaded) as local_uri:
                progress = (
                    ProgressPercentage(local_uri, file_for_msg=src, msg="Uploading:")
                    if log.isEnabledFor(ProgressPercentage.log_level)
                    else None
                )
                with (
                    time_this(log, msg=timer_msg, args=timer_args),
                    self._use_threads_temp_override(multithreaded),
                ):
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

        for page in s3_paginator.paginate(Bucket=self._bucket, Prefix=prefix, Delimiter="/"):
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
        with S3ResourceHandle(mode, log, self) as handle:
            if "b" in mode:
                yield handle
            else:
                if encoding is None:
                    encoding = sys.getdefaultencoding()
                # cast because the protocol is compatible, but does not have
                # BytesIO in the inheritance tree
                with io.TextIOWrapper(cast(io.BytesIO, handle), encoding=encoding, write_through=True) as sub:
                    yield sub

    def generate_presigned_get_url(self, *, expiration_time_seconds: int) -> str:
        # Docstring inherited
        return self._generate_presigned_url("get_object", expiration_time_seconds)

    def generate_presigned_put_url(self, *, expiration_time_seconds: int) -> str:
        # Docstring inherited
        return self._generate_presigned_url("put_object", expiration_time_seconds)

    def _generate_presigned_url(self, method: str, expiration_time_seconds: int) -> str:
        url = self.client.generate_presigned_url(
            method,
            Params={"Bucket": self._bucket, "Key": self.relativeToPathRoot},
            ExpiresIn=expiration_time_seconds,
        )
        if self.fragment:
            resource = ResourcePath(url)
            url = str(resource.replace(fragment=self.fragment))
        return url
