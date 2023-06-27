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
from lsst.resources.tests import GenericTestCase


class MemoryTestCase(GenericTestCase, unittest.TestCase):
    """Generic tests of the mem URI."""

    scheme = "mem"
    netloc = "unknown"


class MemoryReadTestCase(unittest.TestCase):
    """Simple tests of I/O with mem URI."""

    def setUp(self):
        self.root_uri = ResourcePath("mem://x/y.z")

    def test_exists(self):
        """Always exist."""
        self.assertTrue(self.root_uri.exists())

    def test_local(self):
        with self.assertRaises(RuntimeError):
            with self.root_uri.as_local():
                pass


if __name__ == "__main__":
    unittest.main()
