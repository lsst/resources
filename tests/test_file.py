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
import pathlib
import unittest
import unittest.mock

from lsst.resources import ResourcePath
from lsst.resources.tests import GenericReadWriteTestCase, GenericTestCase

TESTDIR = os.path.abspath(os.path.dirname(__file__))


class FileTestCase(GenericTestCase, unittest.TestCase):
    scheme = "file"
    netloc = "localhost"

    def test_env_var(self):
        """Test that environment variables are expanded."""

        with unittest.mock.patch.dict(os.environ, {"MY_TEST_DIR": "/a/b/c"}):
            uri = ResourcePath("${MY_TEST_DIR}/d.txt")
        self.assertEqual(uri.path, "/a/b/c/d.txt")
        self.assertEqual(uri.scheme, "file")

        # This will not expand
        uri = ResourcePath("${MY_TEST_DIR}/d.txt", forceAbsolute=False)
        self.assertEqual(uri.path, "${MY_TEST_DIR}/d.txt")
        self.assertFalse(uri.scheme)

    def test_ospath(self):
        """File URIs have ospath property."""

        file = ResourcePath(self._make_uri("a/test.txt"))
        self.assertEqual(file.ospath, "/a/test.txt")
        self.assertEqual(file.ospath, file.path)

        # A Schemeless URI can take unquoted files but will be quoted
        # when it becomes a file URI.
        something = "/a#/???.txt"
        file = ResourcePath(something, forceAbsolute=True)
        self.assertEqual(file.scheme, "file")
        self.assertEqual(file.ospath, something, "From URI: {file}")
        self.assertNotIn("???", file.path)

    def test_path_lib(self):
        """File URIs can be created from pathlib"""
        file = ResourcePath(self._make_uri("a/test.txt"))

        path_file = pathlib.Path(file.ospath)
        from_path = ResourcePath(path_file)
        self.assertEqual(from_path.ospath, file.ospath)

    def test_schemeless_root(self):
        root = ResourcePath(self._make_uri("/root"))
        via_root = ResourcePath("b.txt", root=root)
        self.assertEqual(via_root.ospath, "/root/b.txt")


class FileReadWriteTestCase(GenericReadWriteTestCase, unittest.TestCase):
    scheme = "file"
    netloc = "localhost"
    testdir = TESTDIR
    transfer_modes = ("move", "copy", "link", "hardlink", "symlink", "relsymlink")

    def test_transfer_identical(self):
        """Test overwrite of identical files.

        Only relevant for local files.
        """
        dir1 = self.tmpdir.join("dir1", forceDirectory=True)
        dir1.mkdir()
        self.assertTrue(dir1.exists())
        dir2 = self.tmpdir.join("dir2", forceDirectory=True)
        # A symlink can't include a trailing slash.
        dir2_ospath = dir2.ospath
        if dir2_ospath.endswith("/"):
            dir2_ospath = dir2_ospath[:-1]
        os.symlink(dir1.ospath, dir2_ospath)

        # Write a test file.
        src_file = dir1.join("test.txt")
        content = "0123456"
        src_file.write(content.encode())

        # Construct URI to destination that should be identical.
        dest_file = dir2.join("test.txt")
        self.assertTrue(dest_file.exists())
        self.assertNotEqual(src_file, dest_file)

        # Transfer it over itself.
        dest_file.transfer_from(src_file, transfer="symlink", overwrite=True)
        new_content = dest_file.read().decode()
        self.assertEqual(content, new_content)

    def test_local_temporary(self):
        """Create temporary local file if no prefix specified."""
        with ResourcePath.temporary_uri(suffix=".json") as tmp:
            self.assertEqual(tmp.getExtension(), ".json", f"uri: {tmp}")
            self.assertTrue(tmp.isabs(), f"uri: {tmp}")
            self.assertFalse(tmp.exists(), f"uri: {tmp}")
            tmp.write(b"abcd")
            self.assertTrue(tmp.exists(), f"uri: {tmp}")
            self.assertTrue(tmp.isTemporary)
            self.assertTrue(tmp.isLocal)

            # If we now ask for a local form of this temporary file
            # it should still be temporary and it should not be deleted
            # on exit.
            with tmp.as_local() as loc:
                self.assertEqual(tmp, loc)
                self.assertTrue(loc.isTemporary)
            self.assertTrue(tmp.exists())
        self.assertFalse(tmp.exists(), f"uri: {tmp}")

    def test_transfers_from_local(self):
        """Extra tests for local transfers."""

        target = self.tmpdir.join("a/target.txt")
        with ResourcePath.temporary_uri() as tmp:
            tmp.write(b"")
            self.assertTrue(tmp.isTemporary)

            # Symlink transfers for temporary resources should
            # trigger a debug message.
            for transfer in ("symlink", "relsymlink"):
                with self.assertLogs("lsst.resources", level="DEBUG") as cm:
                    target.transfer_from(tmp, transfer)
                target.remove()
                self.assertIn("Using a symlink for a temporary", "".join(cm.output))

            # Force the target directory to be created.
            target.transfer_from(tmp, "move")
            self.assertFalse(tmp.exists())

            # Temporary file now gone so transfer should not work.
            with self.assertRaises(FileNotFoundError):
                target.transfer_from(tmp, "move", overwrite=True)


if __name__ == "__main__":
    unittest.main()
