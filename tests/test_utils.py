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
import subprocess
import sys
import unittest
import unittest.mock
from concurrent.futures.process import BrokenProcessPool
from typing import Any

import lsst.resources._resourcePath as resource_path
from lsst.resources import ResourcePath
from lsst.resources._resourcePath import (
    _clear_pool_executor_cache,
    _make_pool_executor,
    _pool_executor,
)
from lsst.resources.file import FileResourcePath
from lsst.resources.s3 import S3ResourcePath
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
            if method not in multiprocessing.get_all_start_methods():
                continue
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

    @unittest.mock.patch.dict(os.environ, {}, clear=False)
    def test_cap_limits_the_default(self) -> None:
        os.environ.pop("LSST_RESOURCES_NUM_WORKERS", None)
        _clear_worker_caches()
        self.assertLessEqual(_get_num_workers(S3ResourcePath._max_workers), S3ResourcePath._max_workers)

    @unittest.mock.patch.dict(os.environ, {"LSST_RESOURCES_NUM_WORKERS": "99"})
    def test_explicit_request_overrides_the_scheme_cap(self) -> None:
        _clear_worker_caches()
        self.assertEqual(_get_num_workers(S3ResourcePath._max_workers), 99)


class PoolReuseTestCase(unittest.TestCase):
    """Tests for reuse of process pools across calls."""

    def tearDown(self) -> None:
        _clear_pool_executor_cache()

    def test_process_pools_are_reused(self) -> None:
        with _pool_executor(concurrent.futures.ProcessPoolExecutor, 2) as first:
            pass
        with _pool_executor(concurrent.futures.ProcessPoolExecutor, 2) as second:
            pass
        self.assertIs(first, second)
        # Still usable after both blocks have exited.
        self.assertEqual(list(second.map(int, ["1", "2"])), [1, 2])

    def test_different_sizes_replace_the_cached_pool(self) -> None:
        with _pool_executor(concurrent.futures.ProcessPoolExecutor, 2) as small:
            self.assertEqual(small.submit(int, "1").result(), 1)
        with _pool_executor(concurrent.futures.ProcessPoolExecutor, 3) as large:
            self.assertEqual(large.submit(int, "2").result(), 2)
        self.assertIsNot(small, large)
        with self.assertRaises(RuntimeError):
            small.submit(int, "1")
        # Returning to an earlier size creates a new pool, and also shuts
        # down the larger one instead of leaving its workers alive.
        with _pool_executor(concurrent.futures.ProcessPoolExecutor, 2) as replacement:
            self.assertIsNot(replacement, small)
            self.assertEqual(replacement.submit(int, "3").result(), 3)
        with self.assertRaises(RuntimeError):
            large.submit(int, "1")

    @unittest.mock.patch.dict(os.environ, {}, clear=False)
    @unittest.mock.patch.object(FileResourcePath, "_max_workers", 3)
    @unittest.mock.patch.object(FileResourcePath, "_min_chunk_size", 1)
    def test_batch_size_does_not_replace_the_cached_pool(self) -> None:
        os.environ.pop("LSST_RESOURCES_NUM_WORKERS", None)
        _clear_worker_caches()
        _clear_pool_executor_cache()
        few = [ResourcePath(__file__).updatedFile(f"missing{n}.txt") for n in range(2)]
        many = [ResourcePath(__file__).updatedFile(f"missing{n}.txt") for n in range(64)]

        # A batch that occupies only a couple of workers must still be given a
        # pool sized for the scheme, or the next larger batch would replace it.
        for uris in (few, many, few):
            FileResourcePath._mexists_pool(concurrent.futures.ProcessPoolExecutor, uris)
            cached = resource_path._POOL_EXECUTOR_CACHE
            assert cached is not None
            self.assertEqual(cached[1], 3)
            if uris is few:
                first = cached[2]
        self.assertIs(resource_path._POOL_EXECUTOR_CACHE[2], first)

    @unittest.mock.patch.dict(os.environ, {}, clear=False)
    def test_s3_batch_size_does_not_size_the_pool(self) -> None:
        os.environ.pop("LSST_RESOURCES_NUM_WORKERS", None)
        _clear_worker_caches()
        recorded: list[int] = []

        class _RecordingExecutor(concurrent.futures.ThreadPoolExecutor):
            def __init__(self, max_workers: int, **kwargs: Any) -> None:
                recorded.append(max_workers)
                super().__init__(max_workers=max_workers, **kwargs)

        uri = ResourcePath("s3://bucket/object.txt")
        with unittest.mock.patch.object(S3ResourcePath, "_delete_objects_wrapper", return_value={}):
            S3ResourcePath._mremove_with_pool(_RecordingExecutor, [(uri,)])
        self.assertEqual(recorded, [_get_num_workers()])

    def test_thread_pools_are_not_reused(self) -> None:
        with _pool_executor(concurrent.futures.ThreadPoolExecutor, 2) as first:
            pass
        with _pool_executor(concurrent.futures.ThreadPoolExecutor, 2) as second:
            pass
        self.assertIsNot(first, second)
        # A thread pool is cheap, so it is shut down when the block ends.
        with self.assertRaises(RuntimeError):
            first.submit(int, "1")

    def test_clearing_the_cache_shuts_pools_down(self) -> None:
        with _pool_executor(concurrent.futures.ProcessPoolExecutor, 2) as executor:
            pass
        _clear_pool_executor_cache()
        with self.assertRaises(RuntimeError):
            executor.submit(int, "1")
        # The next request builds a fresh pool.
        with _pool_executor(concurrent.futures.ProcessPoolExecutor, 2) as replacement:
            self.assertIsNot(replacement, executor)

    def test_a_broken_pool_is_replaced(self) -> None:
        with _pool_executor(concurrent.futures.ProcessPoolExecutor, 2) as executor:
            # Workers start lazily, so submit before there is anything to kill.
            list(executor.map(int, ["1", "2"]))
        # Kill the workers so the pool is unusable.
        for process in list(executor._processes.values()):
            process.terminate()
            process.join()
        with self.assertRaises(concurrent.futures.BrokenExecutor):
            with _pool_executor(concurrent.futures.ProcessPoolExecutor, 2) as broken:
                broken.submit(int, "1").result()
        with _pool_executor(concurrent.futures.ProcessPoolExecutor, 2) as replacement:
            self.assertIsNot(replacement, executor)
            self.assertEqual(replacement.submit(int, "1").result(), 1)

    @unittest.mock.patch.object(FileResourcePath, "_min_chunk_size", 1)
    def test_bulk_operations_discard_broken_pools(self) -> None:
        uris = [ResourcePath(__file__), ResourcePath(__file__).updatedFile("missing.txt")]
        executor_class = concurrent.futures.ProcessPoolExecutor
        operations = {
            "mexists": lambda: FileResourcePath._mexists_pool(executor_class, uris, num_workers=2),
            "mremove": lambda: FileResourcePath._mremove_pool(executor_class, uris, num_workers=2),
            "mtransfer": lambda: ResourcePath._mtransfer(
                executor_class, "copy", [(uris[0], uris[1])], do_raise=False
            ),
            "s3_mremove": lambda: S3ResourcePath._mremove_with_pool(
                executor_class, [(uris[0],), (uris[1],)], num_workers=2
            ),
        }
        for name, operation in operations.items():
            with self.subTest(operation=name):
                with _pool_executor(executor_class, 2) as broken:
                    pass

                def fail_submission(*args: Any, **kwargs: Any) -> concurrent.futures.Future:
                    future = concurrent.futures.Future()
                    future.set_exception(BrokenProcessPool("worker died"))
                    return future

                # Fail the futures, not submit(), to exercise the exceptions
                # caught inside each bulk operation's result loop.
                with (
                    unittest.mock.patch.object(broken, "submit", side_effect=fail_submission),
                    unittest.mock.patch("lsst.resources._resourcePath._get_num_workers", return_value=2),
                ):
                    results = operation()
                if name == "mexists":
                    self.assertTrue(all(value is False for value in results.values()))
                else:
                    self.assertTrue(all(not value.success for value in results.values()))
                with _pool_executor(executor_class, 2) as replacement:
                    self.assertIsNot(replacement, broken)
                    self.assertEqual(replacement.submit(int, "1").result(), 1)

    def test_import_without_fork_support(self) -> None:
        # Load dependencies before hiding the hook: POSIX versions of some
        # stdlib modules (such as random) assume the hook is available.
        subprocess.run(
            [
                sys.executable,
                "-c",
                "import os, importlib; "
                "import lsst.resources._resourcePath as resource_path; "
                "hasattr(os, 'register_at_fork') and delattr(os, 'register_at_fork'); "
                "importlib.reload(resource_path)",
            ],
            check=True,
            capture_output=True,
        )


if __name__ == "__main__":
    unittest.main()
