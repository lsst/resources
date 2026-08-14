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
import unittest

from lsst.resources import ResourcePath
from lsst.resources.tests import GenericReadWriteTestCase, GenericTestCase, make_remote_test_uri
from lsst.resources.utils import makeTestTempDir, removeTestTempDir

TESTDIR = os.path.abspath(os.path.dirname(__file__))


class RemoteTestTestCase(GenericTestCase, unittest.TestCase):
    """File-specific generic test cases."""

    scheme = "remote-test"
    netloc = "localhost"


class RemoteTestReadWriteTestCase(GenericReadWriteTestCase, unittest.TestCase):
    """File tests involving reading and writing of data."""

    scheme = "remote-test"
    netloc = "localhost"
    testdir = TESTDIR
    # transfer_modes deliberately left at the remote default of copy/move.
    # Link modes are refused for a non-local resource, which is the whole
    # point of this scheme.

    @classmethod
    def setUpClass(cls) -> None:
        # This scheme is backed by the local file system, so the URI path has
        # to name a real writable directory. The netloc is not used.
        cls._tmproot = makeTestTempDir(TESTDIR)
        cls.base_path = cls._tmproot
        super().setUpClass()

    @classmethod
    def tearDownClass(cls) -> None:
        removeTestTempDir(cls._tmproot)
        super().tearDownClass()

    def test_not_local(self) -> None:
        """Test that the resource is not local and localizes to temp."""
        test_file = self.root_uri.join("test_file.txt")
        test_file.write(b"abc")

        self.assertEqual(test_file.scheme, "remote-test")
        self.assertEqual(test_file.read(), b"abc")
        self.assertFalse(test_file.isLocal)

        with test_file.as_local() as loc:
            # Tests that ospath does not raise and that the "local" version
            # of the file is at a different location.
            self.assertNotEqual(loc.ospath, test_file.ospath)


class RemoteTestUriTestCase(unittest.TestCase):
    """Tests for the remote-test URI helper."""

    def setUp(self):
        self.root = makeTestTempDir(TESTDIR)

    def tearDown(self):
        removeTestTempDir(self.root)

    def testScheme(self):
        uri = make_remote_test_uri(self.root)
        self.assertEqual(uri.scheme, "remote-test")
        self.assertFalse(uri.isLocal)
        self.assertEqual(uri.ospath.rstrip("/"), self.root)

    def testSpecialCharacters(self):
        awkward = os.path.join(self.root, "a dir with spaces")
        os.makedirs(awkward)
        uri = make_remote_test_uri(awkward)

        # Interpolating the path into a string that already has a scheme
        # leaves the spaces unencoded, so the helper has to encode them.
        naive = ResourcePath(f"remote-test://localhost{awkward}/", forceDirectory=True)
        self.assertIn(" ", naive.geturl())
        self.assertNotIn(" ", uri.geturl())

        self.assertEqual(uri.ospath.rstrip("/"), awkward)

        child = uri.join("file.json", forceDirectory=False)
        child.write(b"{}")
        self.assertEqual(child.read(), b"{}")

    def testFile(self):
        uri = make_remote_test_uri(os.path.join(self.root, "a file.json"), forceDirectory=False)
        self.assertFalse(uri.isdir())
        self.assertIn("a%20file.json", uri.geturl())
        self.assertTrue(uri.ospath.endswith("a file.json"))


if __name__ == "__main__":
    unittest.main()
