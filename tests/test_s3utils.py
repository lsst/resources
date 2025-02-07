# This file is part of daf_butler.
#
# Developed for the LSST Data Management System.
# This product includes software developed by the LSST Project
# (http://www.lsst.org).
# See the COPYRIGHT file at the top-level directory of this distribution
# for details of code ownership.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import unittest
from unittest import mock

try:
    import boto3
    from botocore.exceptions import ParamValidationError

    try:
        from moto import mock_aws  # v5
    except ImportError:
        from moto import mock_s3 as mock_aws
except ImportError:
    boto3 = None

from urllib3.exceptions import LocationParseError

from lsst.resources import ResourcePath
from lsst.resources.location import Location
from lsst.resources.s3utils import (
    _parse_endpoint_config,
    bucketExists,
    clean_test_environment_for_s3,
    getS3Client,
    s3CheckFileExists,
)


@unittest.skipIf(not boto3, "Warning: boto3 AWS SDK not found!")
class S3UtilsTestCase(unittest.TestCase):
    """Test for the S3 related utilities."""

    bucketName = "test_bucket_name"
    fileName = "testFileName"

    def setUp(self):
        self.enterContext(clean_test_environment_for_s3())
        self.enterContext(mock_aws())

        self.client = getS3Client()
        try:
            self.client.create_bucket(Bucket=self.bucketName)
            self.client.put_object(Bucket=self.bucketName, Key=self.fileName, Body=b"test content")
        except self.client.exceptions.BucketAlreadyExists:
            pass

    def tearDown(self):
        objects = self.client.list_objects(Bucket=self.bucketName)
        if "Contents" in objects:
            for item in objects["Contents"]:
                self.client.delete_object(Bucket=self.bucketName, Key=item["Key"])

        self.client.delete_bucket(Bucket=self.bucketName)

    def testBucketExists(self):
        self.assertTrue(bucketExists(f"{self.bucketName}"))
        self.assertFalse(bucketExists(f"{self.bucketName}_no_exist"))

    def testCephBucket(self):
        with mock.patch.dict(os.environ, {"LSST_DISABLE_BUCKET_VALIDATION": "N"}):
            self.assertEqual(os.environ["LSST_DISABLE_BUCKET_VALIDATION"], "N")
            local_client = getS3Client()
            with self.assertRaises(ParamValidationError):
                bucketExists("foo:bar", local_client)
        with mock.patch.dict(os.environ, {"LSST_DISABLE_BUCKET_VALIDATION": "1"}):
            self.assertEqual(os.environ["LSST_DISABLE_BUCKET_VALIDATION"], "1")
            local_client = getS3Client()
            self.assertFalse(bucketExists("foo:bar", local_client))

    def testFileExists(self):
        self.assertTrue(s3CheckFileExists(client=self.client, bucket=self.bucketName, path=self.fileName)[0])
        self.assertFalse(
            s3CheckFileExists(client=self.client, bucket=self.bucketName, path=self.fileName + "_NO_EXIST")[0]
        )

        datastoreRootUri = f"s3://{self.bucketName}/"
        uri = f"s3://{self.bucketName}/{self.fileName}"

        buri = ResourcePath(uri)
        location = Location(datastoreRootUri, self.fileName)

        self.assertTrue(s3CheckFileExists(client=self.client, path=buri)[0])
        # just to make sure the overloaded keyword works correctly
        self.assertTrue(s3CheckFileExists(buri, client=self.client)[0])
        self.assertTrue(s3CheckFileExists(client=self.client, path=location)[0])

        # make sure supplying strings resolves correctly too
        self.assertTrue(s3CheckFileExists(uri, client=self.client))
        self.assertTrue(s3CheckFileExists(uri))

    def test_parsing_profile_config(self):
        with self.assertRaises(LocationParseError):
            _parse_endpoint_config(
                "https://AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/FK7MDENG/FbPxRfiCYEXAMPLEKEY@endpoint.com"
            )

        parsed = _parse_endpoint_config(
            "https://AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI%2FK7MDENG%2FbPxRfiCYEXAMPLEKEY@endpoint.com"
        )
        self.assertEqual(parsed.endpoint_url, "https://endpoint.com")
        self.assertEqual(parsed.access_key_id, "AKIAIOSFODNN7EXAMPLE")
        self.assertEqual(parsed.secret_access_key, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")

        simple = _parse_endpoint_config("https://other.endpoint.com")
        self.assertEqual(simple.endpoint_url, "https://other.endpoint.com")
        self.assertIsNone(simple.access_key_id)
        self.assertIsNone(simple.secret_access_key)

        with self.assertRaisesRegex(ValueError, "S3 access key and secret not in expected format."):
            _parse_endpoint_config("https://key@endpoint.com")


if __name__ == "__main__":
    unittest.main()
