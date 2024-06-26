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

__all__ = (
    "clean_test_environment",
    "getS3Client",
    "s3CheckFileExists",
    "bucketExists",
    "setAwsEnvCredentials",
    "unsetAwsEnvCredentials",
    "backoff",
    "all_retryable_errors",
    "max_retry_time",
    "retryable_io_errors",
    "retryable_client_errors",
    "_TooManyRequestsError",
    "clean_test_environment_for_s3",
)

import functools
import os
import re
import urllib.parse
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from http.client import HTTPException, ImproperConnectionState
from types import ModuleType
from typing import TYPE_CHECKING, Any, NamedTuple, cast
from unittest.mock import patch

from botocore.exceptions import ClientError
from botocore.handlers import validate_bucket_name
from deprecated.sphinx import deprecated
from urllib3.exceptions import HTTPError, RequestError
from urllib3.util import Url, parse_url

if TYPE_CHECKING:
    from unittest import TestCase


try:
    import boto3
except ImportError:
    boto3 = None

try:
    import botocore
except ImportError:
    botocore = None


from ._resourcePath import ResourcePath
from .location import Location

# https://pypi.org/project/backoff/
try:
    import backoff
except ImportError:

    class Backoff:
        """Mock implementation of the backoff class."""

        @staticmethod
        def expo(func: Callable, *args: Any, **kwargs: Any) -> Callable:
            return func

        @staticmethod
        def on_exception(func: Callable, *args: Any, **kwargs: Any) -> Callable:
            return func

    backoff = cast(ModuleType, Backoff)


class _TooManyRequestsError(Exception):
    """Private exception that can be used for 429 retry.

    botocore refuses to deal with 429 error itself so issues a generic
    ClientError.
    """

    pass


# settings for "backoff" retry decorators. these retries are belt-and-
# suspenders along with the retries built into Boto3, to account for
# semantic differences in errors between S3-like providers.
retryable_io_errors = (
    # http.client
    ImproperConnectionState,
    HTTPException,
    # urllib3.exceptions
    RequestError,
    HTTPError,
    # built-ins
    TimeoutError,
    ConnectionError,
    # private
    _TooManyRequestsError,
)

# Client error can include NoSuchKey so retry may not be the right
# thing. This may require more consideration if it is to be used.
retryable_client_errors = (
    # botocore.exceptions
    ClientError,
    # built-ins
    PermissionError,
)


# Combine all errors into an easy package. For now client errors
# are not included.
all_retryable_errors = retryable_io_errors
max_retry_time = 60


@deprecated(
    reason="This has been replaced by a new function, clean_test_environment_for_s3()."
    " Will be removed after v26.2023.5000",
    version="26.2023.5000",
    category=FutureWarning,
)
def clean_test_environment(testcase: TestCase) -> None:
    """Clear S3_ENDPOINT_URL then restore it at the end of a test.

    Parameters
    ----------
    testcase : `unittest.TestCase`
        Reference to the test being run; used to add a cleanup function.
    """
    endpoint = os.environ.get("S3_ENDPOINT_URL")

    if not endpoint:
        return
    os.environ["S3_ENDPOINT_URL"] = ""

    def cleanup() -> None:
        if endpoint is not None:
            os.environ["S3_ENDPOINT_URL"] = endpoint

    testcase.addCleanup(cleanup)


@contextmanager
def clean_test_environment_for_s3() -> Iterator[None]:
    """Reset S3 environment to ensure that unit tests with a mock S3 can't
    accidentally reference real infrastructure.
    """
    with patch.dict(
        os.environ,
        {
            "AWS_ACCESS_KEY_ID": "test-access-key",
            "AWS_SECRET_ACCESS_KEY": "test-secret-access-key",
        },
    ) as patched_environ:
        for var in (
            "S3_ENDPOINT_URL",
            "AWS_SECURITY_TOKEN",
            "AWS_SESSION_TOKEN",
            "AWS_PROFILE",
            "AWS_SHARED_CREDENTIALS_FILE",
            "AWS_CONFIG_FILE",
        ):
            patched_environ.pop(var, None)
        # Clear the cached boto3 S3 client instances.
        # This helps us avoid a potential situation where the client could be
        # instantiated before moto mocks are installed, which would prevent the
        # mocks from taking effect.
        _get_s3_client.cache_clear()
        yield


def getS3Client(profile: str | None = None) -> boto3.client:
    """Create a S3 client with AWS (default) or the specified endpoint.

    Parameters
    ----------
    profile : `str`, optional
        The name of an S3 profile describing which S3 service to use.

    Returns
    -------
    s3client : `botocore.client.S3`
        A client of the S3 service.

    Notes
    -----
    If an explicit profile name is specified, its configuration will be read
    from an environment variable named ``LSST_RESOURCES_S3_PROFILE_<profile>``
    if it exists.  Note that the name of the profile is case sensitive.  This
    configuration is specified in the format: ``https://<access key ID>:<secret
    key>@<s3 endpoint hostname>``. If the access key ID or secret key values
    contain slashes, the slashes must be URI-encoded (replace "/" with "%2F").

    If profile is `None` or the profile environment variable was not set, the
    configuration is read from the environment variable ``S3_ENDPOINT_URL``.
    If it is not specified, the default AWS endpoint is used.

    The access key ID and secret key are optional -- if not specified, they
    will be looked up via the `AWS credentials file
    <https://boto3.amazonaws.com/v1/documentation/api/latest/guide/credentials.html>`_.

    If the environment variable LSST_DISABLE_BUCKET_VALIDATION exists
    and has a value that is not empty, "0", "f", "n", or "false"
    (case-insensitive), then bucket name validation is disabled.  This
    disabling allows Ceph multi-tenancy colon separators to appear in
    bucket names.
    """
    if boto3 is None:
        raise ModuleNotFoundError("Could not find boto3. Are you sure it is installed?")
    if botocore is None:
        raise ModuleNotFoundError("Could not find botocore. Are you sure it is installed?")

    endpoint = None
    if profile is not None:
        var_name = f"LSST_RESOURCES_S3_PROFILE_{profile}"
        endpoint = os.environ.get(var_name, None)
    if not endpoint:
        endpoint = os.environ.get("S3_ENDPOINT_URL", None)
    if not endpoint:
        endpoint = None  # Handle ""

    disable_value = os.environ.get("LSST_DISABLE_BUCKET_VALIDATION", "0")
    skip_validation = not re.search(r"^(0|f|n|false)?$", disable_value, re.I)

    return _get_s3_client(endpoint, profile, skip_validation)


@functools.lru_cache
def _get_s3_client(endpoint: str | None, profile: str | None, skip_validation: bool) -> boto3.client:
    # Helper function to cache the client for this endpoint
    config = botocore.config.Config(read_timeout=180, retries={"mode": "adaptive", "max_attempts": 10})

    endpoint_config = _parse_endpoint_config(endpoint)

    if endpoint_config.access_key_id is not None and endpoint_config.secret_access_key is not None:
        # We already have the necessary configuration for the profile, so do
        # not pass the profile to boto3.  boto3 will raise an exception if the
        # profile is not defined in its configuration file, whether or not it
        # needs to read the configuration from it.
        profile = None
    session = boto3.Session(profile_name=profile)

    client = session.client(
        "s3",
        endpoint_url=endpoint_config.endpoint_url,
        aws_access_key_id=endpoint_config.access_key_id,
        aws_secret_access_key=endpoint_config.secret_access_key,
        config=config,
    )
    if skip_validation:
        client.meta.events.unregister("before-parameter-build.s3", validate_bucket_name)
    return client


class _EndpointConfig(NamedTuple):
    endpoint_url: str | None = None
    access_key_id: str | None = None
    secret_access_key: str | None = None


def _parse_endpoint_config(endpoint: str | None) -> _EndpointConfig:
    if not endpoint:
        return _EndpointConfig()

    parsed = parse_url(endpoint)

    # Strip the username/password portion of the URL from the result.
    endpoint_url = Url(host=parsed.host, path=parsed.path, port=parsed.port, scheme=parsed.scheme).url

    access_key_id = None
    secret_access_key = None
    if parsed.auth:
        split = parsed.auth.split(":")
        if len(split) != 2:
            raise ValueError("S3 access key and secret not in expected format.")
        access_key_id, secret_access_key = split
        access_key_id = urllib.parse.unquote(access_key_id)
        secret_access_key = urllib.parse.unquote(secret_access_key)

    return _EndpointConfig(
        endpoint_url=endpoint_url, access_key_id=access_key_id, secret_access_key=secret_access_key
    )


def s3CheckFileExists(
    path: Location | ResourcePath | str,
    bucket: str | None = None,
    client: boto3.client | None = None,
) -> tuple[bool, int]:
    """Return if the file exists in the bucket or not.

    Parameters
    ----------
    path : `Location`, `ResourcePath` or `str`
        Location or ResourcePath containing the bucket name and filepath.
    bucket : `str`, optional
        Name of the bucket in which to look. If provided, path will be assumed
        to correspond to be relative to the given bucket.
    client : `boto3.client`, optional
        S3 Client object to query, if not supplied boto3 will try to resolve
        the credentials as in order described in its manual_.

    Returns
    -------
    exists : `bool`
        True if key exists, False otherwise.
    size : `int`
        Size of the key, if key exists, in bytes, otherwise -1.

    Notes
    -----
    S3 Paths are sensitive to leading and trailing path separators.

    .. _manual: https://boto3.amazonaws.com/v1/documentation/api/latest/guide/\
    configuration.html#configuring-credentials
    """
    if boto3 is None:
        raise ModuleNotFoundError("Could not find boto3. Are you sure it is installed?")

    if client is None:
        client = getS3Client()

    if isinstance(path, str):
        if bucket is not None:
            filepath = path
        else:
            uri = ResourcePath(path)
            bucket = uri.netloc
            filepath = uri.relativeToPathRoot
    elif isinstance(path, ResourcePath | Location):
        if bucket is None:
            bucket = path.netloc
        filepath = path.relativeToPathRoot
    else:
        raise TypeError(f"Unsupported path type: {path!r}.")

    try:
        obj = client.head_object(Bucket=bucket, Key=filepath)
        return (True, obj["ContentLength"])
    except client.exceptions.ClientError as err:
        # resource unreachable error means key does not exist
        errcode = err.response["ResponseMetadata"]["HTTPStatusCode"]
        if errcode == 404:
            return (False, -1)
        # head_object returns 404 when object does not exist only when user has
        # s3:ListBucket permission. If list permission does not exist a 403 is
        # returned. In practical terms this generally means that the file does
        # not exist, but it could also mean user lacks s3:GetObject permission:
        # https://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectHEAD.html
        # I don't think its possible to discern which case is it with certainty
        if errcode == 403:
            raise PermissionError(
                "Forbidden HEAD operation error occurred. "
                "Verify s3:ListBucket and s3:GetObject "
                "permissions are granted for your IAM user. "
            ) from err
        if errcode == 429:
            # boto3, incorrectly, does not automatically retry with 429
            # so instead we raise an explicit retry exception for backoff.
            raise _TooManyRequestsError(str(err)) from err
        raise


def bucketExists(bucketName: str, client: boto3.client | None = None) -> bool:
    """Check if the S3 bucket with the given name actually exists.

    Parameters
    ----------
    bucketName : `str`
        Name of the S3 Bucket.
    client : `boto3.client`, optional
        S3 Client object to query, if not supplied boto3 will try to resolve
        the credentials by calling `getS3Client`.

    Returns
    -------
    exists : `bool`
        True if it exists, False if no Bucket with specified parameters is
        found.
    """
    if boto3 is None:
        raise ModuleNotFoundError("Could not find boto3. Are you sure it is installed?")

    if client is None:
        client = getS3Client()
    try:
        client.get_bucket_location(Bucket=bucketName)
        return True
    except client.exceptions.NoSuchBucket:
        return False


@deprecated(
    reason="This function could accidentally leave real credentials in the environment during testing."
    " A new function, clean_test_environment_for_s3(), can be used to set up mock credentials."
    " Will be removed after v26.2023.5000",
    version="26.2023.5000",
    category=FutureWarning,
)
def setAwsEnvCredentials(
    accessKeyId: str = "dummyAccessKeyId", secretAccessKey: str = "dummySecretAccessKey"
) -> bool:
    """Set AWS credentials environmental variables.

    Parameters
    ----------
    accessKeyId : `str`
        Value given to AWS_ACCESS_KEY_ID environmental variable. Defaults to
        `dummyAccessKeyId`.
    secretAccessKey : `str`
        Value given to AWS_SECRET_ACCESS_KEY environmental variable. Defaults
        to `dummySecretAccessKey`.

    Returns
    -------
    setEnvCredentials : `bool`
        True when environmental variables were set, False otherwise.

    Notes
    -----
    If either AWS_ACCESS_KEY_ID or AWS_SECRET_ACCESS_KEY are not set, both
    values are overwritten to ensure that the values are consistent.
    """
    if "AWS_ACCESS_KEY_ID" not in os.environ or "AWS_SECRET_ACCESS_KEY" not in os.environ:
        os.environ["AWS_ACCESS_KEY_ID"] = accessKeyId
        os.environ["AWS_SECRET_ACCESS_KEY"] = secretAccessKey
        return True
    return False


@deprecated(
    reason="This has been replaced by a new function, clean_test_environment_for_s3()."
    " Will be removed after v26.2023.5000",
    version="26.2023.5000",
    category=FutureWarning,
)
def unsetAwsEnvCredentials() -> None:
    """Unset AWS credential environment variables.

    Unsets the AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environmental
    variables.
    """
    if "AWS_ACCESS_KEY_ID" in os.environ:
        del os.environ["AWS_ACCESS_KEY_ID"]
    if "AWS_SECRET_ACCESS_KEY" in os.environ:
        del os.environ["AWS_SECRET_ACCESS_KEY"]
