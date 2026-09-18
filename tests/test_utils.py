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
import unittest.mock

from lsst.resources import ResourcePath
from lsst.resources.file import FileResourcePath
from lsst.resources.s3 import S3ResourcePath
from lsst.resources.utils import (
    MAX_WORKERS,
    _get_configured_num_workers,
    _get_default_num_workers,
    _get_num_workers,
)


def _clear_worker_caches() -> None:
    """Discard memoized worker-count lookups."""
    _get_configured_num_workers.cache_clear()
    _get_default_num_workers.cache_clear()


class NumWorkersTestCase(unittest.TestCase):
    """Tests for the worker-count calculation."""

    def setUp(self) -> None:
        _clear_worker_caches()

    def tearDown(self) -> None:
        _clear_worker_caches()

    @unittest.mock.patch.dict(os.environ, {}, clear=False)
    def test_default_is_capped(self) -> None:
        os.environ.pop("LSST_RESOURCES_NUM_WORKERS", None)
        _clear_worker_caches()
        self.assertLessEqual(_get_num_workers(), MAX_WORKERS)
        self.assertEqual(_get_num_workers(2), 2)

    @unittest.mock.patch.dict(os.environ, {"LSST_RESOURCES_NUM_WORKERS": "99"})
    def test_explicit_request_bypasses_cap(self) -> None:
        _clear_worker_caches()
        self.assertEqual(_get_num_workers(), 99)
        self.assertEqual(_get_num_workers(2), 99)

    def test_docstring_is_present(self) -> None:
        # An f-string in the leading position is not a docstring.
        self.assertIsNotNone(_get_num_workers.__doc__)


class WorkerCapTestCase(unittest.TestCase):
    """Tests for per-scheme worker caps."""

    def setUp(self) -> None:
        _clear_worker_caches()

    def tearDown(self) -> None:
        _clear_worker_caches()

    def test_schemes_share_the_default_cap(self) -> None:
        self.assertEqual(ResourcePath._max_workers, MAX_WORKERS)
        self.assertEqual(FileResourcePath._max_workers, MAX_WORKERS)
        self.assertEqual(S3ResourcePath._max_workers, MAX_WORKERS)

    @unittest.mock.patch.dict(os.environ, {}, clear=False)
    @unittest.mock.patch.object(FileResourcePath, "_max_workers", 2)
    def test_an_overridden_cap_is_honored(self) -> None:
        os.environ.pop("LSST_RESOURCES_NUM_WORKERS", None)
        _clear_worker_caches()
        self.assertEqual(_get_num_workers(FileResourcePath._max_workers), 2)

    @unittest.mock.patch.dict(os.environ, {"LSST_RESOURCES_NUM_WORKERS": "99"})
    def test_explicit_request_overrides_the_scheme_cap(self) -> None:
        _clear_worker_caches()
        self.assertEqual(_get_num_workers(S3ResourcePath._max_workers), 99)


if __name__ == "__main__":
    unittest.main()
