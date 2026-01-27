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
import re
import sys
import unittest
import unittest.mock

from lsst.resources import ResourcePath
from lsst.resources.eups import EupsResourcePath
from lsst.resources.tests import GenericTestCase

TESTDIR = os.path.abspath(os.path.dirname(__file__))
PKG_DIR = os.path.join(TESTDIR, "packages", "eups")
PACKAGE_PATH = os.path.join(TESTDIR, "packages")


class EupsTestCase(GenericTestCase, unittest.TestCase):
    """Generic test of resource URIs."""

    scheme = "eups"
    netloc = "pkg"

    @classmethod
    def setUpClass(cls) -> None:
        # The actual value does not matter for these tests.
        os.environ["PKG_DIR"] = PKG_DIR
        super().setUpClass()

    @classmethod
    def tearDownClass(cls) -> None:
        del os.environ["PKG_DIR"]
        super().tearDownClass()

    def test_relative(self) -> None:
        # This test uses two additional netlocs which need corresponding
        # environment variables to function. The values do not matter.
        with unittest.mock.patch.dict(os.environ, {"OTHER_DIR": "x", "MY.HOST_DIR": "y"}):
            super().test_relative()


class EupsReadTestCase(unittest.TestCase):
    """Test that EUPS information can be read.

    EUPS resources can be thought of as being read only even if the
    underlying URI is a ``file`` URI.
    """

    scheme = "eups"
    netloc = "pkg"

    @classmethod
    def setUpClass(cls) -> None:
        # The actual value does not matter for these tests.
        os.environ["PKG_DIR"] = PKG_DIR
        super().setUpClass()

    @classmethod
    def tearDownClass(cls) -> None:
        del os.environ["PKG_DIR"]
        super().tearDownClass()

    def setUp(self):
        self.root = f"{self.scheme}://{self.netloc}"
        self.root_uri = ResourcePath(self.root)

    def test_read(self):
        uri = self.root_uri.join("config/test.txt")
        self.assertTrue(uri.exists(), f"Check {uri} exists")

        content = uri.read().decode()
        self.assertIn("A test config.", content)

        with uri.as_local() as local_uri:
            self.assertEqual(local_uri.scheme, "file")
            self.assertTrue(local_uri.exists())

        truncated = uri.read(size=9).decode()
        self.assertEqual(truncated, content[:9])

        # Check that directory determination can work directly without the
        # trailing slash.
        d = self.root_uri.join("config")
        self.assertTrue(d.isdir())
        self.assertTrue(d.dirLike)

        d = self.root_uri.join("config/", forceDirectory=True)
        self.assertTrue(d._proxy.dirLike)  # Ensure that dir-ness propagates to proxy.
        self.assertTrue(d.exists(), f"Check directory {d} exists")
        self.assertTrue(d.isdir())

        with self.assertRaises(IsADirectoryError):
            with d.as_local() as local_uri:
                pass

        j = d.join("test.txt")
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
        uri = self.root_uri.join("config/test.txt")
        with uri.open("rb") as buffer:
            content = buffer.read()
        self.assertEqual(uri.read(), content)

        with uri.open("r") as buffer:
            content = buffer.read()
        self.assertEqual(uri.read().decode(), content)

    def test_walk(self):
        """Test that we can find file resources.

        Try to find resources in this package. Python does not care whether
        a resource is a Python file or anything else.
        """
        resource = ResourcePath(f"{self.scheme}://{self.netloc}/")
        resources = set(ResourcePath.findFileResources([resource]))

        # Make sure that walk() can run and knows this is a directory.
        cfg = resource.join("config/")
        _, dirs, files = next(cfg.walk())
        self.assertEqual(dirs, [])
        self.assertEqual(set(files), {"test.txt", "test2.yaml"})

        # Do not try to list all possible options. Files can move around
        # and cache files can appear.
        subset = {
            ResourcePath(f"{self.scheme}://{self.netloc}/config/test.txt"),
            ResourcePath(f"{self.scheme}://{self.netloc}/config/test2.yaml"),
        }
        for r in subset:
            self.assertIn(r, resources)

        resources = set(
            ResourcePath.findFileResources(
                [ResourcePath(f"{self.scheme}://{self.netloc}/")], file_filter=r".*\.json"
            )
        )
        self.assertEqual(resources, set())

        # Compare regex with str.
        regex = r".*\.yaml"
        y_files_str = list(resource.walk(file_filter=regex))
        y_files_re = list(resource.walk(file_filter=re.compile(regex)))
        self.assertGreater(len(y_files_str), 1)
        self.assertEqual(y_files_str, y_files_re)

        bad_dir = ResourcePath(f"{self.scheme}://bad.module/a/dir/")
        self.assertTrue(bad_dir.isdir())
        with self.assertRaises(ValueError):
            list(bad_dir.walk())

    def test_env_var(self):
        """Test that environment variables are converted."""
        with unittest.mock.patch.dict(os.environ, {"MY_TEST_DIR": TESTDIR}):
            for env_string in ("$MY_TEST_DIR", "${MY_TEST_DIR}"):
                uri = ResourcePath(f"{env_string}/data/dir1/a.yaml")
                self.assertEqual(uri.path, "/data/dir1/a.yaml")
                self.assertEqual(uri.scheme, "eups")
                self.assertEqual(uri.netloc, "my_test")
                self.assertTrue(uri.exists())


class EupsAsResourcesReadTestCase(EupsReadTestCase):
    """Test that EUPS information can be read via resources.

    EUPS resources can be thought of as being read only even if the
    underlying URI is a ``file`` URI.
    """

    scheme = "eups"
    netloc = "pkg1"

    @classmethod
    def setUpClass(cls) -> None:
        # The actual value does not matter for these tests.
        sys.path.append(PACKAGE_PATH)
        super().setUpClass()

    @classmethod
    def tearDownClass(cls) -> None:
        sys.path.remove(PACKAGE_PATH)
        super().tearDownClass()


class EupsAsResourcesReadTestCase2(EupsAsResourcesReadTestCase):
    """Test that EUPS information can be read via resources with lsst-style
    package.

    EUPS resources can be thought of as being read only even if the
    underlying URI is a ``file`` URI.
    """

    scheme = "eups"
    netloc = "pkg2_sub"

    @classmethod
    def setUpClass(cls) -> None:
        # To avoid confusion with other lsst packages, override the default
        # prefix that is added to the EUPS name.
        cls.prefix = EupsResourcePath._default_namespace
        EupsResourcePath._default_namespace = "prefix"
        super().setUpClass()

    @classmethod
    def tearDownClass(cls) -> None:
        EupsResourcePath._default_namespace = cls.prefix
        super().tearDownClass()


if __name__ == "__main__":
    unittest.main()
