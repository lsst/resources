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

import contextlib
import datetime
import functools
import os
import pathlib
import threading
import unittest
import unittest.mock
import urllib.parse
from collections.abc import Callable, Iterator
from typing import Any

from lsst.resources import ResourceInfo, ResourcePath, ResourcePathExpression
from lsst.resources.file import FileResourcePath
from lsst.resources.tests import GenericReadWriteTestCase, GenericTestCase
from lsst.resources.utils import makeTestTempDir, removeTestTempDir

TESTDIR = os.path.abspath(os.path.dirname(__file__))


class SimpleTestCase(unittest.TestCase):
    """Basic tests for file URIs."""

    def test_instance(self):
        for example in (
            "xxx",
            ResourcePath("xxx"),
            pathlib.Path("xxx"),
            urllib.parse.urlparse("file:///xxx"),
        ):
            self.assertIsInstance(example, ResourcePathExpression)

        for example in ({1, 2, 3}, 42, self):
            self.assertNotIsInstance(example, ResourcePathExpression)


class FileTestCase(GenericTestCase, unittest.TestCase):
    """File-specific generic test cases."""

    scheme = "file"
    netloc = "localhost"

    def test_env_var(self):
        """Test that environment variables are expanded."""
        with unittest.mock.patch.dict(os.environ, {"MY_TEST_DIRX": "/a/b/c"}):
            uri = ResourcePath("${MY_TEST_DIRX}/d.txt")
        self.assertEqual(uri.path, "/a/b/c/d.txt")
        self.assertEqual(uri.scheme, "file")

        # This will not expand
        uri = ResourcePath("${MY_TEST_DIRX}/d.txt", forceAbsolute=False)
        self.assertEqual(uri.path, "${MY_TEST_DIRX}/d.txt")
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
        """File URIs can be created from pathlib."""
        file = ResourcePath(self._make_uri("a/test.txt"))

        path_file = pathlib.Path(file.ospath)
        from_path = ResourcePath(path_file)
        self.assertEqual(from_path.ospath, file.ospath)

    def test_schemeless_root(self):
        root = ResourcePath(self._make_uri("/root"))
        via_root = ResourcePath("b.txt", root=root)
        self.assertEqual(via_root.ospath, "/root/b.txt")

    def test_get_info(self):
        now = datetime.datetime.now(tz=datetime.UTC)
        with ResourcePath.temporary_uri(suffix=".txt") as target:
            target.write(b"abc")

            info = target.get_info()
            self.assertIsInstance(info, ResourceInfo)
            self.assertTrue(info.uri.endswith(".txt"))
            self.assertTrue(info.is_file)
            self.assertEqual(info.size, 3)
            self.assertEqual(info.checksums, {})
            self.assertEqual(info.last_modified.tzinfo, datetime.UTC)
            self.assertGreaterEqual(info.last_modified.timestamp(), now.timestamp() - 1.0)

            dirinfo = target.parent().get_info()
            self.assertEqual(dirinfo.uri, str(target.parent()))
            self.assertFalse(dirinfo.is_file)
            self.assertEqual(dirinfo.size, 0)
            self.assertGreaterEqual(dirinfo.last_modified.timestamp(), 0)
            self.assertEqual(dirinfo.checksums, {})


TEST_UMASK = 0o0333


class FileReadWriteTestCase(GenericReadWriteTestCase, unittest.TestCase):
    """File tests involving reading and writing of data."""

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

        with ResourcePath.temporary_uri(suffix=".yaml", delete=False) as tmp:
            tmp.write(b"1234")
            self.assertTrue(tmp.exists(), f"uri: {tmp}")
        # If the file doesn't exist there is nothing to clean up so a failure
        # here is not a problem.
        self.assertTrue(tmp.exists(), f"uri: {tmp} should still exist")

        # If removal does not work it's worth reporting that as an error.
        tmp.remove()

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

    def test_write_with_restrictive_umask(self):
        self._test_file_with_restrictive_umask(lambda target: target.write(b"123"))

    def test_transfer_from_with_restrictive_umask(self):
        def cb(target):
            with ResourcePath.temporary_uri() as tmp:
                tmp.write(b"")
                target.transfer_from(tmp, "copy")

        self._test_file_with_restrictive_umask(cb)

    def test_mkdir_with_restrictive_umask(self):
        self._test_with_restrictive_umask(lambda target: target.mkdir())

    def test_temporary_uri_with_restrictive_umask(self):
        with _override_umask(TEST_UMASK):
            with ResourcePath.temporary_uri() as tmp:
                tmp.write(b"")
                self.assertTrue(tmp.exists())

    def _test_file_with_restrictive_umask(self, callback):
        def inner_cb(target):
            callback(target)

            # Make sure the umask was respected for the file itself
            file_mode = os.stat(target.ospath).st_mode
            self.assertEqual(file_mode & TEST_UMASK, 0)

        self._test_with_restrictive_umask(inner_cb)

    def _test_with_restrictive_umask(self, callback):
        """Make sure that parent directories for a file can be created even if
        the user has set a process umask that restricts the write and traverse
        bits.
        """
        with _override_umask(TEST_UMASK):
            target = self.tmpdir.join("a/b/target.txt")
            callback(target)
            self.assertTrue(target.exists())

            dir_b_path = os.path.dirname(target.ospath)
            dir_a_path = os.path.dirname(dir_b_path)
            for dir in [dir_a_path, dir_b_path]:
                # Make sure we only added the minimum permissions needed for it
                # to work (owner-write and owner-traverse)
                mode = os.stat(dir).st_mode
                self.assertEqual(mode & TEST_UMASK, 0o0300, f"Permissions incorrect for {dir}: {mode:o}")


class BulkOperationTestCase(unittest.TestCase):
    """Tests for batched bulk operations on local files."""

    def setUp(self) -> None:
        self.tmpdir = ResourcePath(makeTestTempDir(TESTDIR), forceDirectory=True)

    def tearDown(self) -> None:
        removeTestTempDir(self.tmpdir.ospath)

    def _make_files(self, prefix: str, count: int) -> list[ResourcePath]:
        uris = [self.tmpdir.join(f"{prefix}{n}.txt") for n in range(count)]
        for uri in uris:
            uri.write(b"")
        return uris

    @unittest.mock.patch.object(FileResourcePath, "_min_chunk_size", 1)
    def test_chunk_sizes(self) -> None:
        items = list(range(5))

        # Fewer items than chunk slots gives one item per chunk.
        chunks = FileResourcePath._chunk_work(items, 32, FileResourcePath._min_chunk_size)
        self.assertEqual(len(chunks), 5)
        self.assertTrue(all(len(c) == 1 for c in chunks))

        # More items than chunk slots gives evenly sized chunks.
        chunks = FileResourcePath._chunk_work(items, 1, FileResourcePath._min_chunk_size)
        self.assertEqual([len(c) for c in chunks], [2, 2, 1])

        # An empty input yields no chunks at all.
        self.assertEqual(FileResourcePath._chunk_work([], 4, 1), [])

    def test_chunk_size_floor(self) -> None:
        items = list(range(10))

        # A batch that would otherwise be spread thinly is kept in one piece,
        # which is the signal to the caller to handle it without a pool.
        self.assertEqual([len(c) for c in FileResourcePath._chunk_work(items[:4], 32, 4)], [4])

        # The floor never makes chunks larger than the worker count calls for.
        self.assertEqual([len(c) for c in FileResourcePath._chunk_work(items, 1, 4)], [4, 4, 2])

    def test_empty_bulk_operations_are_no_ops(self) -> None:
        self.assertEqual(ResourcePath.mremove([]), {})
        self.assertEqual(ResourcePath.mexists([]), {})
        self.assertEqual(ResourcePath.mtransfer("copy", []), {})

    @unittest.mock.patch.object(FileResourcePath, "_min_chunk_size", 1)
    def test_removal_failure_does_not_abandon_the_rest(self) -> None:
        uris = self._make_files("f", 20)
        # Remove one out from under the batch so that its own removal raises.
        uris[1].remove()

        results = ResourcePath.mremove(uris, do_raise=False)

        self.assertEqual(len(results), len(uris))
        self.assertFalse(results[uris[1]].success)
        self.assertIsInstance(results[uris[1]].exception, FileNotFoundError)
        for uri in uris[2:]:
            self.assertTrue(results[uri].success, f"{uri} should have been removed")
            self.assertFalse(uri.exists())

    @unittest.mock.patch.object(FileResourcePath, "_min_chunk_size", 1)
    def test_existence_check_reports_each_uri(self) -> None:
        present = self._make_files("p", 20)
        absent = self.tmpdir.join("gone.txt")

        results = ResourcePath.mexists([*present, absent])

        self.assertEqual(len(results), len(present) + 1)
        self.assertTrue(all(results[uri] for uri in present))
        self.assertFalse(results[absent])

    @unittest.mock.patch.object(FileResourcePath, "_min_chunk_size", 1)
    def test_existence_check_treats_an_error_as_missing(self) -> None:
        uris = self._make_files("e", 20)
        failing = uris[1].ospath
        real_exists = FileResourcePath.exists

        def flaky(self: FileResourcePath) -> bool:
            if self.ospath == failing:
                raise PermissionError("cannot stat")
            return real_exists(self)

        with unittest.mock.patch.object(FileResourcePath, "exists", flaky):
            results = ResourcePath.mexists(uris)

        # The failure is reported as absent and the rest are still checked.
        self.assertFalse(results[uris[1]])
        self.assertTrue(all(results[uri] for uri in uris if uri != uris[1]))

    def test_transfer_of_many_files(self) -> None:
        sources = self._make_files("src", 50)
        for i, src in enumerate(sources):
            src.write(f"{i}".encode())
        destinations = [self.tmpdir.join(f"dest{n}.txt") for n in range(len(sources))]

        results = ResourcePath.mtransfer("copy", zip(sources, destinations, strict=True))

        self.assertEqual(len(results), len(sources))
        self.assertTrue(all(res.success for res in results.values()))
        for i, dest in enumerate(destinations):
            self.assertEqual(dest.read().decode(), str(i))

    def test_transfer_failure_does_not_abandon_the_rest(self) -> None:
        sources = self._make_files("s", 20)
        destinations = [self.tmpdir.join(f"d{n}.txt") for n in range(len(sources))]
        # An existing target fails when overwriting is not allowed.
        destinations[1].write(b"in the way")

        results = ResourcePath.mtransfer("copy", zip(sources, destinations, strict=True), do_raise=False)

        self.assertEqual(len(results), len(sources))
        self.assertFalse(results[destinations[1]].success)
        for dest in destinations[2:]:
            self.assertTrue(results[dest].success, f"{dest} should have been written")
            self.assertTrue(dest.exists())

    def test_transfer_registers_undo_actions(self) -> None:
        sources = self._make_files("u", 20)
        destinations = [self.tmpdir.join(f"undo{n}.txt") for n in range(len(sources))]
        transaction = _RecordingTransaction()

        results = ResourcePath.mtransfer(
            "copy", zip(sources, destinations, strict=True), overwrite=True, transaction=transaction
        )

        self.assertTrue(all(res.success for res in results.values()))
        # Every transfer must be undoable by the caller that supplied the
        # transaction, no matter which worker performed it.
        self.assertEqual(len(transaction.undone), len(sources))

        for undo in transaction.undone:
            undo()
        self.assertFalse(any(dest.exists() for dest in destinations))


class _RecordingTransaction:
    """Transaction that collects the undo actions registered against it."""

    def __init__(self) -> None:
        self.undone: list[Callable[[], Any]] = []
        self._lock = threading.Lock()

    @contextlib.contextmanager
    def undoWith(self, name: str, undoFunc: Callable, *args: Any, **kwargs: Any) -> Iterator[None]:
        yield None
        with self._lock:
            self.undone.append(functools.partial(undoFunc, *args, **kwargs))


@contextlib.contextmanager
def _override_umask(temp_umask):
    old = os.umask(temp_umask)
    try:
        yield
    finally:
        os.umask(old)


if __name__ == "__main__":
    unittest.main()
