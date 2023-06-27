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

from lsst.resources.tests import GenericTestCase

try:
    from google.cloud import storage
except ImportError:
    storage = None


@unittest.skipIf(not storage, "Warning: google-cloud-storage not found!")
class GenericGCSTestCase(GenericTestCase, unittest.TestCase):
    """Generic tests of google cloud storage URI format."""

    scheme = "gs"
    netloc = "my_bucket"


if __name__ == "__main__":
    unittest.main()
