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

import concurrent.futures
import multiprocessing
import os
import unittest
import unittest.mock
from typing import Any

from lsst.resources._resourcePath import _make_pool_executor
from lsst.resources.utils import (
    MAX_WORKERS,
    _get_configured_num_workers,
    _get_default_num_workers,
    _get_num_workers,
    _init_pool_worker,
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

    @unittest.mock.patch.dict(os.environ, {"LSST_RESOURCES_NUM_WORKERS": "99"})
    @unittest.mock.patch("lsst.resources.utils._IS_POOL_WORKER", True)
    def test_pool_worker_uses_one_worker(self) -> None:
        _clear_worker_caches()
        self.assertEqual(_get_num_workers(), 1)
        self.assertEqual(_get_num_workers(99), 1)

    def test_docstring_is_present(self) -> None:
        # An f-string in the leading position is not a docstring.
        self.assertIsNotNone(_get_num_workers.__doc__)


class PoolExecutorTestCase(unittest.TestCase):
    """Tests for worker-count propagation into pool executors."""

    def setUp(self) -> None:
        _clear_worker_caches()

    def tearDown(self) -> None:
        _clear_worker_caches()

    def test_process_worker_reports_one_worker(self) -> None:
        # The fork start method is the one where a child inherits the parent's
        # memoized state, so both methods must be checked.
        for method in ("fork", "spawn"):
            with self.subTest(start_method=method):
                parent_before = _get_num_workers()
                context = multiprocessing.get_context(method)
                with concurrent.futures.ProcessPoolExecutor(
                    max_workers=2,
                    mp_context=context,
                    initializer=_init_pool_worker,
                ) as executor:
                    # The callable has to come from an installed module. The
                    # spawn start method pickles it by reference and the child
                    # process cannot import this test module.
                    observed = list(executor.map(_get_num_workers, [MAX_WORKERS] * 4))
                self.assertEqual(observed, [1, 1, 1, 1])
                self.assertEqual(_get_num_workers(), parent_before)

    def test_thread_pool_does_not_mark_the_parent(self) -> None:
        parent_before = _get_num_workers()
        executor = _make_pool_executor(concurrent.futures.ThreadPoolExecutor, 2)
        with executor:
            observed = list(executor.map(_get_num_workers, [MAX_WORKERS] * 4))
        self.assertEqual(observed, [parent_before] * 4)
        self.assertEqual(_get_num_workers(), parent_before)

    def test_process_pool_receives_the_requested_size(self) -> None:
        recorded: list[int] = []

        class _RecordingExecutor(concurrent.futures.ProcessPoolExecutor):
            def __init__(self, max_workers: int, **kwargs: Any) -> None:
                recorded.append(max_workers)
                super().__init__(max_workers=max_workers, **kwargs)

        # A cold cache must not cause the parent pool to shrink to one.
        _clear_worker_caches()
        _make_pool_executor(_RecordingExecutor, 7).shutdown()
        self.assertEqual(recorded, [7])


if __name__ == "__main__":
    unittest.main()
