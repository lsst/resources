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

import re
import unittest

from lsst.resources import ResourcePath
from lsst.resources.tests import GenericTestCase


class ResourceTestCase(GenericTestCase, unittest.TestCase):
    """Generic test of resource URIs."""

    scheme = "resource"
    netloc = "lsst.resources"


class ResourceReadTestCase(unittest.TestCase):
    """Test that resource information can be read.

    Python package resources are read-only.
    """

    # No resources in this package so need a resource in the main
    # python distribution.
    scheme = "resource"
    netloc = "idlelib"

    def setUp(self):
        self.root = f"{self.scheme}://{self.netloc}"
        self.root_uri = ResourcePath(self.root)

    def test_read(self):
        uri = self.root_uri.join("Icons/README.txt")
        self.assertTrue(uri.exists(), f"Check {uri} exists")

        content = uri.read().decode()
        self.assertIn("IDLE", content)

        with uri.as_local() as local_uri:
            self.assertEqual(local_uri.scheme, "file")
            self.assertTrue(local_uri.exists())

        truncated = uri.read(size=9).decode()
        self.assertEqual(truncated, content[:9])

        # Check that directory determination can work directly without the
        # trailing slash.
        d = self.root_uri.join("Icons")
        self.assertTrue(d.isdir())
        self.assertTrue(d.dirLike)

        d = self.root_uri.join("Icons/", forceDirectory=True)
        self.assertTrue(uri.exists(), f"Check directory {d} exists")
        self.assertTrue(d.isdir())

        with self.assertRaises(IsADirectoryError):
            with d.as_local() as local_uri:
                pass

        j = d.join("README.txt")
        self.assertEqual(uri, j)
        self.assertFalse(j.dirLike)
        self.assertFalse(j.isdir())
        not_there = d.join("not-there.yaml")
        self.assertFalse(not_there.exists())

        bad = ResourcePath(f"{self.scheme}://bad.module/not.yaml")
        multi = ResourcePath.mexists([uri, bad, not_there])
        self.assertTrue(multi[uri])
        self.assertFalse(multi[bad])
        self.assertFalse(multi[not_there])

        # Check that the bad URI works as expected.
        self.assertFalse(bad.exists())
        self.assertFalse(bad.isdir())
        with self.assertRaises(FileNotFoundError):
            bad.read()
        with self.assertRaises(FileNotFoundError):
            with bad.as_local():
                pass
        with self.assertRaises(FileNotFoundError):
            with bad.open("r"):
                pass

        # fsspec is always not implemented.
        with self.assertRaises(NotImplementedError):
            bad.to_fsspec()

    def test_open(self):
        uri = self.root_uri.join("Icons/README.txt")
        with uri.open("rb") as buffer:
            content = buffer.read()
        self.assertEqual(uri.read(), content)

        with uri.open("r") as buffer:
            content = buffer.read()
        self.assertEqual(uri.read().decode(), content)

        # Read only.
        with self.assertRaises(RuntimeError):
            with uri.open("w") as buffer:
                pass

    def test_walk(self):
        """Test that we can find file resources.

        Try to find resources in this package. Python does not care whether
        a resource is a Python file or anything else.
        """
        resource = ResourcePath("resource://lsst.resources/")
        resources = set(ResourcePath.findFileResources([resource]))

        # Do not try to list all possible options. Files can move around
        # and cache files can appear.
        subset = {
            ResourcePath("resource://lsst.resources/_resourceHandles/_s3ResourceHandle.py"),
            ResourcePath("resource://lsst.resources/http.py"),
        }
        for r in subset:
            self.assertIn(r, resources)

        resources = set(
            ResourcePath.findFileResources(
                [ResourcePath("resource://lsst.resources/")], file_filter=r".*\.txt"
            )
        )
        self.assertEqual(resources, set())

        # Compare regex with str.
        regex = r".*\.py"
        py_files_str = list(resource.walk(file_filter=regex))
        py_files_re = list(resource.walk(file_filter=re.compile(regex)))
        self.assertGreater(len(py_files_str), 1)
        self.assertEqual(py_files_str, py_files_re)

        with self.assertRaises(ValueError):
            list(ResourcePath("resource://lsst.resources/http.py").walk())

        bad_dir = ResourcePath(f"{self.scheme}://bad.module/a/dir/")
        self.assertTrue(bad_dir.isdir())
        with self.assertRaises(ValueError):
            list(bad_dir.walk())


if __name__ == "__main__":
    unittest.main()
