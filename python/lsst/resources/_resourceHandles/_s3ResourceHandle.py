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

__all__ = ("S3ResourceHandle",)

import warnings
from collections.abc import Iterable, Mapping
from io import SEEK_CUR, SEEK_END, SEEK_SET, BytesIO, UnsupportedOperation
from logging import Logger
from typing import TYPE_CHECKING

from botocore.exceptions import ClientError
from lsst.utils.introspection import find_outside_stacklevel
from lsst.utils.timer import time_this

from ..s3utils import all_retryable_errors, backoff, max_retry_time
from ._baseResourceHandle import BaseResourceHandle, CloseStatus

if TYPE_CHECKING:
    import boto3


class S3ResourceHandle(BaseResourceHandle[bytes]):
    """S3 specialization of `.BaseResourceHandle`

    Parameters
    ----------
    mode : `str`
        Handle modes as described in the python `io` module.
    log : `~logging.Logger`
        Logger to used when writing messages.
    client : `boto3.client`
        An existing boto3 client that will be used for interacting with the
        remote s3 server.
    bucket : `str`
        The name of the s3 bucket of this resource.
    key : `str`
        The identifier of the resource within the specified bucket.
    newline : `str`
        When doing multiline operations, break the stream on given character.
        Defaults to newline.

    Note
    ----
    It is only possible to incrementally flush this object if each chunk that
    is flushed is above 5MB in size. The flush command is ignored until the
    internal buffer reaches this size, or until close is called, whichever
    comes first.

    Once an instance in write mode is flushed, it is not possible to seek back
    to a position in the byte stream before the flush is executed.

    When opening a resource in read write mode (r+ or w+) no flushing is
    possible, and all data will be buffered until the resource is closed and
    the buffered data will be written. Additionally the entire contents of the
    resource will be loaded into memory upon opening.

    Documentation on the methods of this class line should refer to the
    corresponding methods in the `io` module.

    S3 handles only support operations in binary mode. To get other modes of
    reading and writing, wrap this handle inside an `io.TextIOWrapper` context
    manager. An example of this can be found in `S3ResourcePath`.
    """

    def __init__(
        self, mode: str, log: Logger, client: boto3.client, bucket: str, key: str, newline: bytes = b"\n"
    ):
        super().__init__(mode, log, newline=newline)
        self._client = client
        self._bucket = bucket
        self._key = key
        self._buffer = BytesIO()
        self._position = 0
        self._writable = False
        self._last_flush_position: int | None = None
        self._warned = False
        self._readable = bool({"r", "+"} & set(self._mode))
        self._max_size: int | None = None
        self._recursing = False
        if {"w", "a", "x", "+"} & set(self._mode):
            self._writable = True
            self._multiPartUpload = client.create_multipart_upload(Bucket=bucket, Key=key)
            self._partNo = 1
            self._parts: list[Mapping] = []
            # Below is a workaround for append mode. It basically must read in
            # everything that exists in the file so that it is in the buffer to
            # append to, and subsequently written back out appropriately with
            # any newly added data.
            if {"a", "+"} & set(self._mode):
                # Cheat a bit to get the existing data from the handle using
                # object interfaces, because we know this is safe.
                # Save the requested mode and readability.
                mode_save = self._mode
                read_save = self._readable
                # Update each of these internal variables to ensure the handle
                # is strictly readable.
                self._readable = True
                self._mode += "r"
                self._mode = self._mode.replace("+", "")
                # As mentioned, this reads the existing contents and writes it
                # out into the internal buffer, no writes actually happen until
                # the handle is flushed.
                self.write(self.read())
                # Restore the requested states.
                self._mode = mode_save
                self._readable = read_save
                # Set the state of the stream if the specified mode is read
                # and write.
                if "+" in self._mode:
                    self.seek(0)
                    # If a file is w+ it is read write, but should be truncated
                    # for future writes.
                    if "w" in self._mode:
                        self.truncate()

    def tell(self) -> int:
        return self._position

    @backoff.on_exception(backoff.expo, all_retryable_errors, max_time=max_retry_time)
    def close(self) -> None:
        if self.writable():
            # decide if this is a multipart upload
            if self._parts:
                # indicate that the object is in closing status
                self._closed = CloseStatus.CLOSING
                self.flush()
                with time_this(self._log, msg="Finalize multipart upload to %s", args=(self,)):
                    self._client.complete_multipart_upload(
                        Bucket=self._multiPartUpload["Bucket"],
                        Key=self._multiPartUpload["Key"],
                        UploadId=self._multiPartUpload["UploadId"],
                        MultipartUpload={"Parts": self._parts},
                    )
            else:
                # Put the complete object at once
                with time_this(self._log, msg="Write to %s", args=(self,)):
                    self._client.put_object(Bucket=self._bucket, Key=self._key, Body=self._buffer.getvalue())
        self._closed = CloseStatus.CLOSED

    @property
    def closed(self) -> bool:
        return self._closed == CloseStatus.CLOSED

    def fileno(self) -> int:
        raise UnsupportedOperation("S3 object does not have a file number")

    @backoff.on_exception(backoff.expo, all_retryable_errors, max_time=max_retry_time)
    def flush(self) -> None:
        # If the object is closed, not writeable, or rw flush should be skipped
        # rw mode skips flush because the whole bytestream must be kept in
        # the buffer for seeking reasons.
        if self.closed or not self.writable() or "+" in self._mode:
            return
        # Disallow writes to seek to a position prior to the previous flush
        # this allows multipart uploads to upload content as the stream is
        # written to.
        s3_min_bits = 5 * 1024 * 1024  # S3 flush threshold is 5 Mib.
        if (
            (self.tell() - (self._last_flush_position or 0)) < s3_min_bits
            and self._closed != CloseStatus.CLOSING
            and not self._warned
        ):
            amount = s3_min_bits / (1024 * 1024)
            warnings.warn(
                f"S3 does not support flushing objects less than {amount} Mib, skipping",
                stacklevel=find_outside_stacklevel(
                    "lsst.resources",
                    "backoff",
                    "contextlib",
                    allow_modules={"lsst.resources.tests"},
                ),
            )
            self._warned = True
            return
        # nothing to write, don't create an empty upload
        if self.tell() == 0:
            return
        with time_this(
            self._log,
            msg="Upload multipart %d to %s",
            args=(
                self._partNo,
                self,
            ),
        ):
            response = self._client.upload_part(
                Body=self._buffer.getvalue(),
                Bucket=self._bucket,
                Key=self._key,
                UploadId=self._multiPartUpload["UploadId"],
                PartNumber=self._partNo,
            )
        self._parts.append({"PartNumber": self._partNo, "ETag": response["ETag"]})
        self._partNo += 1
        self._last_flush_position = self._buffer.tell() + (self._last_flush_position or 0)
        self._buffer = BytesIO()

    @property
    def isatty(self) -> bool:
        return False

    def readable(self) -> bool:
        return self._readable

    def readline(self, size: int = -1) -> bytes:
        raise OSError("S3 Does not support line by line reads")

    def readlines(self, hint: int = -1) -> Iterable[bytes]:
        self.seek(0)
        return self.read().split(self._newline)

    def seek(self, offset: int, whence: int = SEEK_SET) -> int:
        if self.writable():
            if self._last_flush_position is not None:
                if whence == SEEK_SET:
                    offset -= self._last_flush_position
                    if offset < 0:
                        raise OSError("S3 ResourceHandle can not seek prior to already flushed positions")
                if whence == SEEK_CUR and (self.tell() - self._last_flush_position) < 0:
                    raise OSError("S3 ResourceHandle can not seek prior to already flushed positions")
                if whence == SEEK_END:
                    raise OSError("S3 ResourceHandle can not seek referencing the end of the resource")
            self._buffer.seek(offset, whence)
            self._position = self._buffer.tell()
        else:
            if whence == SEEK_SET:
                self._position = offset
            elif whence == SEEK_CUR:
                self._position += offset
            elif whence == SEEK_END:
                offset = abs(offset)
                self._position -= offset
        return self._position

    def seekable(self) -> bool:
        return True

    def truncate(self, size: int | None = None) -> int:
        if self.writable():
            self._buffer.truncate(size)
            return self._position
        else:
            raise OSError("S3 ResourceHandle is not writable")

    def writable(self) -> bool:
        return self._writable

    def writelines(self, lines: Iterable[bytes]) -> None:
        if self.writable():
            self._buffer.writelines(lines)
            self._position = self._buffer.tell()
        else:
            raise OSError("S3 ResourceHandle is not writable")

    @backoff.on_exception(backoff.expo, all_retryable_errors, max_time=max_retry_time)
    def read(self, size: int = -1) -> bytes:
        if not self.readable():
            raise OSError("S3 ResourceHandle is not readable")
        # If the object is rw, then read from the internal io buffer
        if "+" in self._mode:
            self._buffer.seek(self._position)
            return self._buffer.read(size)
        # otherwise fetch the appropriate bytes from the remote resource
        if self._max_size is not None and self._position >= self._max_size:
            return b""
        stop = f"{self._position + size - 1}" if size > 0 else ""
        args = {"Range": f"bytes={self._position}-{stop}"}
        try:
            response = self._client.get_object(Bucket=self._bucket, Key=self._key, **args)
            contents = response["Body"].read()
            response["Body"].close()
            self._position += len(contents)
            return contents
        except ClientError as exc:
            if exc.response["ResponseMetadata"]["HTTPStatusCode"] == 416:
                if self._recursing:
                    # This means the function has attempted to read the whole
                    # byte range and failed again, meaning the previous byte
                    # was the last byte
                    return b""
                self._recursing = True
                result = self.read()
                self._max_size = self._position
                self._recursing = False
                return result
            else:
                raise

    def write(self, b: bytes) -> int:
        if self.writable():
            result = self._buffer.write(b)
            self._position = self._buffer.tell()
            return result
        else:
            raise OSError("S3 ResourceHandle is not writable")
