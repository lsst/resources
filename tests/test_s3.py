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

import os
import time
import unittest
from inspect import signature
from unittest import mock
from urllib.parse import parse_qs, urlparse

from lsst.resources import ResourcePath
from lsst.resources.s3 import S3ResourcePath
from lsst.resources.s3utils import clean_test_environment_for_s3
from lsst.resources.tests import GenericReadWriteTestCase, GenericTestCase

try:
    import boto3
    import botocore

    try:
        from moto import mock_aws  # v5
    except ImportError:
        from moto import mock_s3 as mock_aws
except ImportError:
    boto3 = None

    def mock_aws(cls):
        """No-op decorator in case moto mock_aws can not be imported."""
        return cls


try:
    import fsspec
except ImportError:
    fsspec = None


class GenericS3TestCase(GenericTestCase, unittest.TestCase):
    """Generic tests of S3 URIs."""

    scheme = "s3"
    netloc = "my_bucket"


class S3ReadWriteTestCaseBase(GenericReadWriteTestCase):
    """Tests of reading and writing S3 URIs."""

    scheme = "s3"
    s3_endpoint_url: str | None = None

    def setUp(self):
        self.enterContext(clean_test_environment_for_s3())

        # Enable S3 mocking of tests.
        self.enterContext(mock_aws())

        # MOTO needs to know that we expect Bucket bucketname to exist
        s3 = boto3.resource("s3", endpoint_url=self.s3_endpoint_url)
        s3.create_bucket(Bucket=self.bucket)

        super().setUp()

    def tearDown(self):
        s3 = boto3.resource("s3")
        bucket = s3.Bucket(self.bucket)
        try:
            bucket.objects.all().delete()
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] == "404":
                # the key was not reachable - pass
                pass
            else:
                raise

        bucket = s3.Bucket(self.bucket)
        bucket.delete()

        S3ResourcePath.use_threads = None

        super().tearDown()

    def test_bucket_fail(self):
        # Deliberately create URI with unknown bucket.
        uri = ResourcePath("s3://badbucket/something/")

        with self.assertRaises(ValueError):
            uri.mkdir()

        with self.assertRaises(FileNotFoundError):
            uri.remove()

    def test_transfer_progress(self):
        """Test progress bar reporting for upload and download."""
        remote = self.root_uri.join("test.dat")
        remote.write(b"42")
        with ResourcePath.temporary_uri(suffix=".dat") as tmp:
            # Download from S3.
            with self.assertLogs("lsst.resources", level="DEBUG") as cm:
                tmp.transfer_from(remote, transfer="auto")
            self.assertRegex("".join(cm.output), r"test\.dat.*100\%")

            # Upload to S3.
            with self.assertLogs("lsst.resources", level="DEBUG") as cm:
                remote.transfer_from(tmp, transfer="auto", overwrite=True)
            self.assertRegex("".join(cm.output), rf"{tmp.basename()}.*100\%")

    def test_handle(self):
        remote = self.root_uri.join("test_handle.dat")
        with remote.open("wb") as handle:
            self.assertTrue(handle.writable())
            # write 6 megabytes to make sure partial write work
            handle.write(6 * 1024 * 1024 * b"a")
            self.assertEqual(handle.tell(), 6 * 1024 * 1024)
            handle.flush()
            self.assertGreaterEqual(len(handle._multiPartUpload), 1)

            # verify file can't be seeked back
            with self.assertRaises(OSError):
                handle.seek(0)

            # write more bytes
            handle.write(1024 * b"c")

            # seek back and overwrite
            handle.seek(6 * 1024 * 1024)
            handle.write(1024 * b"b")

        with remote.open("rb") as handle:
            self.assertTrue(handle.readable())
            # read the first 6 megabytes
            result = handle.read(6 * 1024 * 1024)
            self.assertEqual(result, 6 * 1024 * 1024 * b"a")
            self.assertEqual(handle.tell(), 6 * 1024 * 1024)
            # verify additional read gets the next part
            result = handle.read(1024)
            self.assertEqual(result, 1024 * b"b")
            # see back to the beginning to verify seeking
            handle.seek(0)
            result = handle.read(1024)
            self.assertEqual(result, 1024 * b"a")

        remote = self.root_uri.join("missing_file.dat")
        with remote.open("rb") as handle:
            with self.assertRaises(FileNotFoundError):
                handle.read()

    def test_url_signing(self):
        self._test_url_signing_case("url-signing-test.txt", b"test123")
        # A zero byte presigned S3 HTTP URL is a weird edge case, because we
        # emulate HEAD requests using a 1-byte GET.
        self._test_url_signing_case("url-signing-test-zero-bytes.txt", b"")
        # Should be the same as a normal case, but check it for paranoia since
        # it's on the boundary of the read size.
        self._test_url_signing_case("url-signing-test-one-byte.txt", b"t")

    def _test_url_signing_case(self, filename: str, test_data: bytes):
        s3_path = self.root_uri.join(filename)

        put_url = s3_path.generate_presigned_put_url(expiration_time_seconds=1800)
        self._check_presigned_url(put_url, 1800)
        get_url = s3_path.generate_presigned_get_url(expiration_time_seconds=3600)
        self._check_presigned_url(get_url, 3600)

        # Moto monkeypatches the 'requests' library to mock access to presigned
        # URLs, so we are able to use HttpResourcePath to access the URLs in
        # this test.
        ResourcePath(put_url).write(test_data)
        get_path = ResourcePath(get_url)
        retrieved = get_path.read()
        self.assertEqual(retrieved, test_data)
        self.assertTrue(get_path.exists())
        self.assertEqual(get_path.size(), len(test_data))

        # Try again with open().
        with get_path.open("rb") as fd:
            self.assertEqual(fd.read(), test_data)

    def test_nonexistent_presigned_url(self):
        s3_path = self.root_uri.join("this-is-a-missing-file.txt")
        get_url = s3_path.generate_presigned_get_url(expiration_time_seconds=3600)
        get_path = ResourcePath(get_url)
        # Check the HttpResourcePath implementation for presigned S3 urls.
        # Nothing has been uploaded to this URL, so it shouldn't exist.
        self.assertFalse(get_path.exists())
        with self.assertRaises(FileNotFoundError):
            get_path.size()

    def _check_presigned_url(self, url: str, expiration_time_seconds: int):
        parsed = urlparse(url)
        self.assertEqual(parsed.scheme, "https")

        actual_expiration_timestamp = int(parse_qs(parsed.query)["Expires"][0])
        current_time = int(time.time())
        expected_expiration_timestamp = current_time + expiration_time_seconds
        # Allow some flex in the expiration time in case this test process goes
        # out to lunch for a while on a busy CI machine
        self.assertLessEqual(abs(expected_expiration_timestamp - actual_expiration_timestamp), 120)

    def test_threading_true(self):
        with mock.patch.dict(os.environ, {"LSST_S3_USE_THREADS": "True"}):
            S3ResourcePath.use_threads = None
            test_resource_path = self.root_uri.join("test_file.dat")
            self.assertTrue(test_resource_path._transfer_config.use_threads)

    def test_implicit_default_threading(self):
        S3ResourcePath.use_threads = None
        boto_default = signature(boto3.s3.transfer.TransferConfig).parameters["use_threads"].default
        test_resource_path = self.root_uri.join("test_file.dat")
        self.assertEqual(test_resource_path._transfer_config.use_threads, boto_default)

    def test_explicit_default_threading(self):
        with mock.patch.dict(os.environ, {"LSST_S3_USE_THREADS": "None"}):
            S3ResourcePath.use_threads = None
            boto_default = signature(boto3.s3.transfer.TransferConfig).parameters["use_threads"].default
            test_resource_path = self.root_uri.join("test_file.dat")
            self.assertEqual(test_resource_path._transfer_config.use_threads, boto_default)

    def test_threading_false(self):
        with mock.patch.dict(os.environ, {"LSST_S3_USE_THREADS": "False"}):
            S3ResourcePath.use_threads = None
            test_resource_path = self.root_uri.join("test_file.dat")
            self.assertFalse(test_resource_path._transfer_config.use_threads)

            self.test_local()

    @unittest.skipIf(fsspec is None, "fsspec is not available")
    def test_fsspec_constructor(self) -> None:
        """Test that we can obtain an s3fs object."""
        uri = self.root_uri.join("test_file.dat")
        fs, path = uri.to_fsspec()
        self.assertEqual(path, f"{uri._bucket}/{uri.relativeToPathRoot}")
        self.assertTrue(hasattr(fs, "open"))

    def test_fsspec(self) -> None:
        raise unittest.SkipTest("fsspec s3fs incompatible with moto")


@unittest.skipIf(not boto3, "Warning: boto3 AWS SDK not found!")
class S3ReadWriteTestCase(S3ReadWriteTestCaseBase, unittest.TestCase):
    """Test S3 with no explicit profile/endpoint specified.
    (``s3://bucketname/...``).
    """

    bucket = "my_2nd_bucket"
    netloc = bucket


@unittest.skipIf(not boto3, "Warning: boto3 AWS SDK not found!")
class S3WithProfileReadWriteTestCase(S3ReadWriteTestCaseBase, unittest.TestCase):
    """Test S3 URLs with explicit profile specified.
    (``s3://profile@bucketname/...``).
    """

    bucket = "3rd_bucket"
    netloc = f"myprofile@{bucket}"
    s3_endpoint_url = "https://endpoint1.test.example"

    def setUp(self):
        # Configure custom S3 endpoints that we can target from tests using
        # non-default profile.
        self.enterContext(
            mock.patch.dict(
                os.environ,
                {
                    "MOTO_S3_CUSTOM_ENDPOINTS": self.s3_endpoint_url,
                    "LSST_RESOURCES_S3_PROFILE_myprofile": "https://access_key:security_key@endpoint1.test.example",
                },
            )
        )

        super().setUp()

    def test_missing_profile(self):
        with self.assertRaises(botocore.exceptions.ProfileNotFound):
            ResourcePath("s3://otherprofile@bucket").read()

    def test_s3_endpoint_url(self):
        with mock.patch.dict(
            os.environ,
            {"S3_ENDPOINT_URL": self.s3_endpoint_url},
        ):
            path = ResourcePath(f"s3://{self.bucket}/test-s3-endpoint-url.txt")
            data = b"123"
            path.write(data)
            self.assertEqual(path.read(), data)
            self.assertIn(
                "https://endpoint1.test.example",
                path.generate_presigned_get_url(expiration_time_seconds=3600),
            )

    def test_uri_syntax(self):
        path1 = ResourcePath("s3://profile@bucket/path")
        self.assertEqual(path1._bucket, "bucket")
        self.assertEqual(path1._profile, "profile")
        path2 = ResourcePath("s3://bucket2/path")
        self.assertEqual(path2._bucket, "bucket2")
        self.assertIsNone(path2._profile)

    def test_ceph_uri_syntax(self):
        # The Ceph S3 'multi-tenant' syntax for buckets can include colons.
        path1 = ResourcePath("s3://profile@ceph:bucket/path")
        self.assertEqual(path1._bucket, "ceph:bucket")
        self.assertEqual(path1._profile, "profile")
        path2 = ResourcePath("s3://ceph:bucket2/path")
        self.assertEqual(path2._bucket, "ceph:bucket2")
        self.assertIsNone(path2._profile)


if __name__ == "__main__":
    unittest.main()
