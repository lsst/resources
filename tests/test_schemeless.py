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

import unittest

from lsst.resources import ResourcePath


class SchemelessTestCase(unittest.TestCase):
    """Test the behavior of a schemeless URI."""

    def test_creation(self) -> None:
        """Test creation from schemeless URI."""
        relative = "a/b/c.txt"
        abspath = "/a/b/c.txt"

        relative_uri = ResourcePath(relative, forceAbsolute=False)
        self.assertFalse(relative_uri.scheme)
        self.assertFalse(relative_uri.isabs())
        self.assertEqual(relative_uri.ospath, relative)
        rel_to_abs = relative_uri.abspath()

        # Converted to a file URI.
        abs_uri = ResourcePath(relative, forceAbsolute=True)
        self.assertEqual(abs_uri.scheme, "file")
        self.assertTrue(abs_uri.isabs())
        self.assertEqual(abs_uri, rel_to_abs)

        # An absolute path is converted to a file URI.
        file_uri = ResourcePath(abspath)
        self.assertEqual(file_uri.scheme, "file")
        self.assertTrue(file_uri.isabs())

        # Use a prefix root.
        prefix = "/a/b/"
        abs_uri = ResourcePath(relative, root=prefix)
        self.assertEqual(abs_uri.ospath, f"{prefix}{relative}")
        self.assertEqual(abs_uri.scheme, "file")

        # Use a file prefix.
        prefix = "file://localhost/a/b/"
        prefix_uri = ResourcePath(prefix)
        file_uri = ResourcePath(relative, root=prefix_uri)
        self.assertEqual(str(file_uri), f"file://{prefix_uri.ospath}{relative}")

        # Fragments should be fine.
        relative_uri = ResourcePath(relative + "#frag", forceAbsolute=False)
        self.assertEqual(str(relative_uri), f"{relative}#frag")

        file_uri = ResourcePath(relative + "#frag", root=prefix_uri)
        self.assertEqual(str(file_uri), f"file://{prefix_uri.ospath}{relative}#frag")

        # Fragments should not be encoded.
        relative_uri = ResourcePath(relative + "#a,b", forceAbsolute=False)
        self.assertEqual(str(relative_uri), f"{relative}#a,b")

        # file URI with # in directory name does not encode fragment.
        file_uri = ResourcePath("./relati#ve/file.yaml#a,v", root=prefix_uri)
        self.assertEqual(str(file_uri), f"file://{prefix_uri.ospath}relati%23ve/file.yaml#a,v")

        # Can not have a root that refers to a file.
        with self.assertRaises(ValueError):
            ResourcePath(
                relative, root=ResourcePath("resource://lsst.resources/something.txt", forceDirectory=False)
            )

        with_root = ResourcePath(relative, root=ResourcePath("resource://lsst.resources/d/"))
        self.assertEqual(with_root.geturl(), "resource://lsst.resources/d/a/b/c.txt")

    def test_isdir(self):
        """Test that isdir() can check the file system."""
        # Get the relative path for the current test file.
        file = ResourcePath(__file__)
        cwd = ResourcePath(".")
        f = ResourcePath(file.relative_to(cwd), forceAbsolute=False)

        self.assertFalse(f.scheme)
        self.assertTrue(f.exists())
        self.assertIsNone(f.dirLike)
        self.assertFalse(f.isdir())

        # Check that the dirLike has not been updated since we know that
        # cwd could change so caching is bad.
        self.assertIsNone(f.dirLike)

        # Check that a file that does not exist does not update the dirLike
        # flag.
        f = ResourcePath("a/b/c_not_here.txt", forceAbsolute=False)
        self.assertFalse(f.scheme)
        self.assertFalse(f.isdir())
        self.assertIsNone(f.dirLike)


if __name__ == "__main__":
    unittest.main()
