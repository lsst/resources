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

import concurrent
import hashlib
import io
import os.path
import random
import shutil
import socket
import stat
import string
import tempfile
import time
import unittest
import zlib
from collections.abc import Callable
from datetime import datetime
from threading import Thread
from typing import Any, cast
from zipfile import ZipFile, ZipInfo

try:
    from cheroot import wsgi
    from wsgidav.wsgidav_app import WsgiDAVApp
except ImportError:
    WsgiDAVApp = None

try:
    import fsspec
except ImportError:
    fsspec = None
    AbstractFileSystem = type

from lsst.resources import ResourcePath
from lsst.resources._resourceHandles._davResourceHandle import (
    DavReadResourceHandle,
)
from lsst.resources.dav import (
    DavResourcePathConfig,
    dav_globals,
)
from lsst.resources.davutils import (
    DavConfig,
    DavConfigPool,
    TokenAuthorizer,
)
from lsst.resources.tests import GenericReadWriteTestCase, GenericTestCase
from lsst.resources.utils import get_tempdir, makeTestTempDir, removeTestTempDir

TESTDIR = os.path.abspath(os.path.dirname(__file__))


class GenericDavTestCase(GenericTestCase, unittest.TestCase):
    """Generic tests of dav URIs."""

    scheme = "dav"
    netloc = "host.example.org"

    def test_dav_root_uri(self):
        root_uri_test_cases = {
            # input : expected
            "dav://host.example.org": "dav://host.example.org/",
            "dav://host.example.org/some/path": "dav://host.example.org/",
            "dav://host.example.org:12345": "dav://host.example.org:12345/",
            "dav://host.example.org:12345/some/path": "dav://host.example.org:12345/",
            "dav://user:password@host.example.org": "dav://user:password@host.example.org/",
            "dav://user:password@host.example.org/some/path": "dav://user:password@host.example.org/",
            "dav://user:password@host.example.org:12345/some/path": "dav://user:password@host.example.org:12345/",
            "dav://user:password@host.example.org/some/path#fragment": "dav://user:password@host.example.org/",
            "dav://user:password@host.example.org/some/path?param=value": "dav://user:password@host.example.org/",
            "dav://user:password@host.example.org/some/path;parameters": "dav://user:password@host.example.org/",
        }
        for path, expected in root_uri_test_cases.items():
            self.assertEqual(ResourcePath(expected), ResourcePath(path).root_uri())

        clean_path_test_cases = {
            # input : expected
            "dav://host.example.org/": "dav://host.example.org/",
            "dav://host.example.org/some/path": "dav://host.example.org/some/path",
            "dav://host.example.org////some/path///": "dav://host.example.org/some/path/",
            "dav://host.example.org/some/path///": "dav://host.example.org/some/path/",
            "dav://host.example.org/some/./././path": "dav://host.example.org/some/path",
            "dav://host.example.org/a/b/c/d/../../": "dav://host.example.org/a/b/",
            "dav://host.example.org/a/b/c/d/../../../../../../": "dav://host.example.org/",
        }
        for path, expected in clean_path_test_cases.items():
            self.assertEqual(ResourcePath(path).geturl(), expected)


class DavReadWriteTestCase(GenericReadWriteTestCase, unittest.TestCase):
    """Test with a real webDAV server, as opposed to mocking responses."""

    scheme = "dav"
    local_files_to_remove: list[str] = []
    MEGABYTE: int = 1024 * 1024

    @classmethod
    def setUpClass(cls):
        cls.webdav_tmpdir = tempfile.mkdtemp(prefix="webdav-server-test-")
        cls.server_thread = None

        # Reinitialize globals.
        dav_globals._reset()

        # Should we test against a running server?
        #
        # This is convenient for testing against real servers in the
        # developer environment by initializing the environment variable
        # LSST_RESOURCES_DAV_TEST_SERVER_URL with the URL of the server, e.g.
        #    dav://host.example.org:1234/path/to/top/dir
        if (test_endpoint := os.getenv("LSST_RESOURCES_DAV_TEST_SERVER_URL")) is not None:
            # Run this test case against the specified server.
            uri = ResourcePath(test_endpoint)
            cls.scheme = uri.scheme
            cls.netloc = uri.netloc
            cls.base_path = uri.path
        elif WsgiDAVApp is not None:
            # WsgiDAVApp is available, launch a local server in its own
            # thread to expose a local temporary directory and run this
            # test case against it.
            cls.port_number = cls._get_port_number()
            cls.stop_webdav_server = False
            cls.server_thread = Thread(
                target=cls._serve_webdav,
                args=(cls, cls.webdav_tmpdir, cls.port_number, lambda: cls.stop_webdav_server),
                daemon=True,
            )
            cls.server_thread.start()

            # Wait for it to start
            time.sleep(1)

            # Initialize the server endpoint
            cls.netloc = f"127.0.0.1:{cls.port_number}"
        else:
            cls.skipTest(
                cls,
                "neither WsgiDAVApp is available nor a webDAV test endpoint is configured to test against",
            )

    @classmethod
    def tearDownClass(cls):
        # Stop the WsgiDAVApp server, if any
        if WsgiDAVApp is not None:
            # Shut down of the webdav server and wait for the thread to exit
            cls.stop_webdav_server = True
            if cls.server_thread is not None:
                cls.server_thread.join()

        # Remove local temporary files
        for file in cls.local_files_to_remove:
            if os.path.exists(file):
                os.remove(file)

        # Remove temp dir
        if cls.webdav_tmpdir:
            shutil.rmtree(cls.webdav_tmpdir, ignore_errors=True)

    def tearDown(self):
        if self.tmpdir:
            self.tmpdir.remove_dir(recursive=True)

        super().tearDown()

    def test_dav_file_handle(self):
        # Upload a new file with known contents.
        contents = "These are some \n bytes to read"
        remote_file = self.tmpdir.join(self._get_file_name())
        self.assertIsNone(remote_file.write(data=contents, overwrite=True))

        # Test that the correct handle is returned.
        with remote_file.open("rb") as handle:
            self.assertIsInstance(handle, DavReadResourceHandle)

        # Test reading byte ranges works
        with remote_file.open("rb") as handle:
            sub_contents = contents[:10]
            handle = cast(DavReadResourceHandle, handle)
            result = handle.read(len(sub_contents)).decode()
            self.assertEqual(result, sub_contents)

            # Verify the position.
            self.assertEqual(handle.tell(), len(sub_contents))

            # Jump back to the beginning and test if reading the whole file
            # prompts the internal buffer to be read.
            handle.seek(0)
            self.assertEqual(handle.tell(), 0)
            result = handle.read().decode()
            self.assertEqual(result, contents)

            # Check that flush works on read-only handle.
            handle.flush()

        # Verify reading as a string handle works as expected.
        with remote_file.open("r") as handle:
            self.assertIsInstance(handle, io.TextIOWrapper)

            handle = cast(io.TextIOWrapper, handle)
            self.assertIsInstance(handle.buffer, DavReadResourceHandle)

            # Check if string methods work.
            result = handle.read()
            self.assertEqual(result, contents)

            # Check that flush works on read-only handle.
            handle.flush()

        # Verify that write modes invoke the default base method
        with remote_file.open("w") as handle:
            self.assertIsInstance(handle, io.StringIO)

    def test_dav_mkdir(self):
        # Check creation and deletion of an empty directory
        subdir = self.tmpdir.join(self._get_dir_name(), forceDirectory=True)
        self.assertIsNone(subdir.mkdir())
        self.assertTrue(subdir.exists())
        self.assertTrue(subdir.isdir())
        self.assertEqual(subdir.size(), 0)

        # Creating an existing remote directory must succeed
        self.assertIsNone(subdir.mkdir())

        # Deleting an existing directory must succeed
        self.assertIsNone(subdir.remove())

        # Deleting a non-existing directory must succeed
        subir_not_exists = self.tmpdir.join(self._get_dir_name(), forceDirectory=True)
        self.assertIsNone(subir_not_exists.remove())

        # Attempting to create a directory at a path where a file exists
        # must raise
        file = self.tmpdir.join(self._get_file_name(), forceDirectory=False)
        file.write(data=None, overwrite=True)
        self.assertTrue(file.exists())

        existing_file = self.tmpdir.join(file.basename(), forceDirectory=True)
        with self.assertRaises(NotADirectoryError):
            self.assertIsNone(existing_file.mkdir())

        # mkdir must create all missing ancestors
        subsubdir = subdir.join("a/b/c/d/e", forceDirectory=True)
        self.assertIsNone(subsubdir.mkdir())
        self.assertTrue(subsubdir.exists())

    def test_dav_upload_download(self):
        # Test upload a randomly-generated file via write() with and without
        # overwrite
        local_file, file_size = self._generate_file()
        with open(local_file, "rb") as f:
            data = f.read()

        remote_file = self.tmpdir.join(self._get_file_name())
        self.assertIsNone(remote_file.write(data, overwrite=True))
        self.assertTrue(remote_file.exists())
        self.assertEqual(remote_file.size(), file_size)

        # Write without overwrite must raise since target file exists
        with self.assertRaises(FileExistsError):
            remote_file.write(data, overwrite=False)

        # Download the file we just uploaded. Compute and compare a digest of
        # the uploaded and downloaded data and ensure they match
        downloaded_data = remote_file.read()
        self.assertEqual(len(downloaded_data), file_size)
        upload_digest = self._compute_digest(data)
        download_digest = self._compute_digest(downloaded_data)
        self.assertEqual(upload_digest, download_digest)
        os.remove(local_file)

    def test_dav_as_local(self):
        contents = str.encode("12345")
        remote_file = self.tmpdir.join(self._get_file_name())
        self.assertIsNone(remote_file.write(data=contents, overwrite=True))
        self.assertTrue(remote_file.exists())
        self.assertEqual(remote_file.size(), len(contents))

        with remote_file._as_local() as local_uri:
            self.assertTrue(local_uri.isTemporary)
            self.assertTrue(os.path.exists(local_uri.ospath))
            self.assertTrue(os.stat(local_uri.ospath).st_size, len(contents))
            self.assertEqual(local_uri.read(), contents)
        self.assertFalse(local_uri.exists())

    def test_dav_size(self):
        # Retrieving the size of a non-existent file must raise.
        remote_file = self.tmpdir.join(self._get_file_name())
        with self.assertRaises(FileNotFoundError):
            remote_file.size()

        # The size of a directory using a file-like path must be zero
        remote_dir = self.tmpdir.join(self._get_dir_name(), forceDirectory=True)
        self.assertIsNone(remote_dir.mkdir())
        self.assertTrue(remote_dir.exists())
        self.assertEqual(remote_dir.size(), 0)

        dir_as_file = ResourcePath(remote_dir.geturl().rstrip("/"), forceDirectory=False)
        self.assertEqual(dir_as_file.size(), 0)

    def test_dav_upload_creates_dir(self):
        # Uploading a file to a non existing directory must ensure its
        # parent directories are automatically created and upload succeeds
        non_existing_dir = self.tmpdir.join(self._get_dir_name(), forceDirectory=True)
        non_existing_dir = non_existing_dir.join(self._get_dir_name(), forceDirectory=True)
        non_existing_dir = non_existing_dir.join(self._get_dir_name(), forceDirectory=True)
        remote_file = non_existing_dir.join(self._get_file_name())

        local_file, file_size = self._generate_file()
        with open(local_file, "rb") as f:
            data = f.read()
        self.assertIsNone(remote_file.write(data, overwrite=True))

        self.assertTrue(remote_file.exists())
        self.assertEqual(remote_file.size(), file_size)
        self.assertTrue(remote_file.parent().exists())

        downloaded_data = remote_file.read()
        upload_digest = self._compute_digest(data)
        download_digest = self._compute_digest(downloaded_data)
        self.assertEqual(upload_digest, download_digest)

    def test_dav_transfer_from(self):
        # Transfer from local file via "copy", with and without overwrite
        remote_file = self.tmpdir.join(self._get_file_name())
        local_file, _ = self._generate_file()
        source_file = ResourcePath(local_file)
        self.assertIsNone(remote_file.transfer_from(source_file, transfer="copy", overwrite=True))
        self.assertTrue(remote_file.exists())
        self.assertEqual(remote_file.size(), source_file.size())
        with self.assertRaises(FileExistsError):
            remote_file.transfer_from(ResourcePath(local_file), transfer="copy", overwrite=False)

        # Transfer from remote file via "copy", with and without overwrite
        source_file = remote_file
        target_file = self.tmpdir.join(self._get_file_name())
        self.assertIsNone(target_file.transfer_from(source_file, transfer="copy", overwrite=True))
        self.assertTrue(target_file.exists())
        self.assertEqual(target_file.size(), source_file.size())

        # Transfer without overwrite must raise since target resource exists
        with self.assertRaises(FileExistsError):
            target_file.transfer_from(source_file, transfer="copy", overwrite=False)

        # Test transfer from local file via "move", with and without overwrite
        source_file = ResourcePath(local_file)
        source_size = source_file.size()
        target_file = self.tmpdir.join(self._get_file_name())
        self.assertIsNone(target_file.transfer_from(source_file, transfer="move", overwrite=True))
        self.assertTrue(target_file.exists())
        self.assertEqual(target_file.size(), source_size)
        self.assertFalse(source_file.exists())

        # Test transfer without overwrite must raise since target resource
        # exists
        local_file, file_size = self._generate_file()
        with self.assertRaises(FileExistsError):
            source_file = ResourcePath(local_file)
            target_file.transfer_from(source_file, transfer="move", overwrite=False)

        # Test transfer from remote file via "move" with and without overwrite
        # must succeed
        source_file = target_file
        source_size = source_file.size()
        target_file = self.tmpdir.join(self._get_file_name())
        self.assertIsNone(target_file.transfer_from(source_file, transfer="move", overwrite=True))
        self.assertTrue(target_file.exists())
        self.assertEqual(target_file.size(), source_size)
        self.assertFalse(source_file.exists())

        # Transfer without overwrite must raise since target resource exists
        with self.assertRaises(FileExistsError):
            source_file = ResourcePath(local_file)
            target_file.transfer_from(source_file, transfer="move", overwrite=False)

    def test_dav_handle(self):
        # Resource handle must succeed
        remote_file = self.tmpdir.join(self._get_file_name())
        data = "abcdefghi"
        self.assertIsNone(remote_file.write(data, overwrite=True))
        with remote_file.open("rb") as handle:
            handle.seek(1)
            self.assertEqual(handle.read(4).decode("utf-8"), data[1:5])

        # If we read the whole file, ensure we cache its contents
        with remote_file.open("rb") as handle:
            handle.read()
            self.assertIsNotNone(handle._cache)

            handle.seek(1)
            self.assertEqual(handle.read(4).decode("utf-8"), data[1:5])

        # Upload a multi-megabyte file and ensure a partial read succeeds
        # without caching the entire file.
        data = io.BytesIO(b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09" * self.MEGABYTE)
        self.assertIsNone(remote_file.write(data, overwrite=True))
        file_size: int = remote_file.size()
        file_offset: int = random.randint(self.MEGABYTE, file_size)
        bytes_to_read: int = random.randint(self.MEGABYTE // 2, self.MEGABYTE)
        with remote_file.open("rb") as handle:
            data.seek(file_offset)
            handle.seek(file_offset)
            self.assertEqual(handle.tell(), data.tell())
            self.assertEqual(handle.read(bytes_to_read), data.read(bytes_to_read))
            self.assertIsNone(handle._cache)

        # Test readinto()
        with remote_file.open("rb") as handle:
            buffer = bytearray(random.randint(self.MEGABYTE, 2 * self.MEGABYTE))
            offset = random.randint(file_size // 3, file_size // 2)

            # Check the returned read count is as expected
            handle.seek(offset)
            count = handle.readinto(buffer)
            self.assertEqual(count, len(buffer))

            # Check the contents of the returned buffer is as expected
            handle.seek(offset)
            self.assertTrue(handle.read(count) == buffer)

    def test_dav_repeated_write(self):
        data = io.BytesIO(b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09" * self.MEGABYTE)
        remote_file = self.tmpdir.join(self._get_file_name())

        # Consecutive writes to the same file must succeed. It was noticed
        # that XRootD server sometimes fail this operation with an error
        # like:
        #
        #    status 423 [Output file /path/to/file is already opened by
        #    1 writer; open denied.]
        self.assertIsNone(remote_file.write(data, overwrite=True))
        self.assertIsNone(remote_file.write(data, overwrite=True))
        self.assertIsNone(remote_file.write(data, overwrite=True))

    def test_dav_remove(self):
        # Deletion of an existing remote file must succeed
        local_file, file_size = self._generate_file()
        with open(local_file, "rb") as f:
            remote_file = self.tmpdir.join(self._get_file_name())
            self.assertIsNone(remote_file.write(f, overwrite=True))

        self.assertTrue(remote_file.exists())
        self.assertEqual(remote_file.size(), file_size)
        self.assertIsNone(remote_file.remove())

        # Deletion of a non-existing remote file must succeed
        non_existing_file = self.tmpdir.join(self._get_file_name())
        self.assertIsNone(non_existing_file.remove())

        # Deletion of a non-empty remote directory must raise
        subdir = self.tmpdir.join(self._get_dir_name(), forceDirectory=True)
        self.assertIsNone(subdir.mkdir())
        self.assertTrue(subdir.exists())
        with open(local_file, "rb") as f:
            remote_file = subdir.join("file_to_remove")
            remote_file.write(f, overwrite=True)
            self.assertTrue(remote_file.exists())
            self.assertEqual(remote_file.size(), file_size)

        with self.assertRaises(IsADirectoryError):
            subdir.remove()
        self.assertTrue(subdir.exists())

        # Recursively removing a deep hierarchy of directories must succeed
        top = subdir
        for level in ["one", "two", "three", "four"]:
            subdir = subdir.join(level, forceDirectory=True)
            subdir.mkdir()
            self.assertTrue(subdir.exists())
            self.assertTrue(subdir.isdir())

        top.remove_dir(recursive=True)
        self.assertFalse(top.exists())

    def test_dav_to_fsspec(self):
        if fsspec is None:
            self.skipTest("fsspec not available")

        # Upload a randomly-generated file via write() with overwrite.
        local_file, file_size = self._generate_file()
        with open(local_file, "rb") as f:
            data = f.read()

        remote_file = self.tmpdir.join(self._get_file_name())
        self.assertIsNone(remote_file.write(data, overwrite=True))
        self.assertTrue(remote_file.exists())
        self.assertEqual(remote_file.size(), file_size)

        # Ensure that the contents of the remote file we just
        # uploaded is identical to the contents of that file when
        # retrieved via fsspec.open(), with and without a context manager.
        fsys, path = remote_file.to_fsspec()
        file = fsys.open(path)
        self.assertEqual(data, file.read())
        file.close()

        with fsys.open(path) as file:
            self.assertEqual(data, file.read())

        # Ensure the file system inherits from `fsspec.AbstractFileSystem`
        # as parquet expects that.
        self.assertTrue(isinstance(fsys, fsspec.AbstractFileSystem))

        # Ensure properties of the remote file are consistent with those
        # same properties retrieved via the file system.
        self.assertTrue(path, remote_file.geturl())
        self.assertTrue(fsys.exists(path))
        self.assertTrue(fsys.isfile(path))
        self.assertFalse(fsys.isdir(path))
        self.assertEqual(fsys.size(path), remote_file.size())
        self.assertEqual(remote_file._stat().last_modified, fsys.modified(path))

        info = fsys.info(path)
        self.assertTrue(info["name"], path)
        self.assertTrue(info["type"], "file")
        self.assertTrue(info["size"], remote_file.size())

        # Ensure that the file system raises with methods attempting to
        # modifying the file system.
        with self.assertRaises(NotImplementedError):
            fsys.rm(path)

        # Ensure that the file system raises with methods not implemented.
        with self.assertRaises(NotImplementedError):
            fsys.fsid()

        not_implemented_methods = [
            fsys.mkdir,
            fsys.makedirs,
            fsys.rmdir,
            fsys.walk,
            fsys.find,
            fsys.walk,
            fsys.find,
            fsys.du,
            fsys.glob,
            fsys.rm_file,
            fsys.rm,
            fsys.touch,
            fsys.ukey,
            fsys.created,
        ]
        for method in not_implemented_methods:
            with self.assertRaises(NotImplementedError):
                method(path="xxx")

        # Ensure that the file system raises with methods with any path
        # different from the only file returned by to_fsspec().
        file_not_found_methods = [fsys.info, fsys.ls, fsys.modified, fsys.size]
        for method in file_not_found_methods:
            with self.assertRaises(FileNotFoundError):
                method(path="xxx")

    def test_dav_parquet_read(self):
        # Check we can read a parquet file via to_fsspec()

        if fsspec is None:
            self.skipTest("fsspec not available")

        try:
            import numpy as np
            import pyarrow as pa  # type: ignore
            import pyarrow.parquet as pq  # type: ignore

            # Create a local parquet file and upload it. Ensure it is bigger
            # than the default buffer size so that it is not entirely
            # cached when read by parquet library.
            num_rows = 1_000_000
            data = {
                "one": np.arange(num_rows, dtype=np.int32),
                "two": np.arange(num_rows, dtype=np.int64),
                "three": np.arange(num_rows, dtype=np.float64),
            }
            table = pa.Table.from_pydict(data)
            local_file = self._make_local_temp_file()
            pq.write_table(table, local_file)
            local_file_size = os.stat(local_file).st_size

            remote_file = self.tmpdir.join("file.parquet")
            with open(local_file, "rb") as file:
                remote_file.write(file, overwrite=True)

            self.assertTrue(remote_file.exists())
            self.assertEqual(remote_file.size(), local_file_size)

            # Read the remote file we just uploaded via parquet, using
            # similar function as used by
            # `lsst.daf.butler.formatters.ParquetFormatter`.
            fsys, path = remote_file.to_fsspec()
            schema = pq.read_schema(path, filesystem=fsys)
            for column in data.keys():
                self.assertTrue(column in schema.names)

            table = pq.read_table(path, filesystem=fsys, use_threads=True, use_pandas_metadata=False)
            for column in data.keys():
                self.assertTrue(column in table.column_names)
            self.assertEqual(table.num_rows, num_rows)
            self.assertEqual(table.num_columns, len(data.keys()))

            # Convert the parquet table to a Python dictionnary and compare
            # its contents with the data originally used to create the
            # parquet file.
            data_from_parquet = table.to_pydict()
            for column in data.keys():
                self.assertTrue(np.array_equal(data[column], data_from_parquet[column]))

        except ImportError:
            self.skipTest("numpy or pyarrow are not available")

    def test_dav_zip(self):
        # Check we can read back a zip file

        # Create a local zip file composed of a random number of identical
        # files.
        local_file, local_file_size = self._generate_file()
        with open(local_file, "rb") as lf:
            local_file_digest = self._compute_digest(lf.read())

        num_members = random.randint(10, 20)
        basename = os.path.basename(local_file)
        member_names = [f"{basename}-{i}" for i in range(num_members)]
        zip_file_name = self._make_local_temp_file()
        with ZipFile(zip_file_name, mode="w") as zf:
            for name in member_names:
                zf.write(local_file, name)

        # Upload the zip file to the server
        with open(zip_file_name, mode="rb") as file:
            remote_zip_file = self.tmpdir.join("example.zip")
            self.assertIsNone(remote_zip_file.write(file, overwrite=True))
            self.assertEqual(os.stat(zip_file_name).st_size, remote_zip_file.size())

        # Read the zip file back and check its contents.
        with remote_zip_file.open("rb") as fd:
            # Check the names of member files match
            zf = ZipFile(fd)
            zip_members = [info.filename for info in zf.infolist()]
            for name in member_names:
                self.assertTrue(name in zip_members)

            # Check the sizes of member files match
            for file_size in [info.file_size for info in zf.infolist()]:
                self.assertTrue(file_size, local_file_size)

            # Check that the contents of a randomly-selected member file
            # is identical to the original file.
            random_member = random.choice(zf.infolist())
            with zf.open(random_member) as member:
                self.assertEqual(local_file_digest, self._compute_digest(member.read()))

        # Concurrently read all the members of the remote zip file
        def download_zip_member(zfile: ZipFile, zinfo: ZipInfo) -> tuple[int, str]:
            # Download member of `zfile` designated by `zinfo` and return
            # its size in bytes and a checksum of its contents.
            with zfile.open(zinfo.filename) as member:
                data = member.read()
                return len(data), self._compute_digest(data)

        with remote_zip_file.open("rb") as fd:
            zfile = ZipFile(fd)
            executor = concurrent.futures.ThreadPoolExecutor(max_workers=10)
            futures = [executor.submit(download_zip_member, zfile, zinfo) for zinfo in zfile.infolist()]

        # Gather results and check they match the expected values
        for future in concurrent.futures.as_completed(futures):
            member_size, member_digest = future.result()
            self.assertEqual(member_size, local_file_size)
            self.assertEqual(member_digest, local_file_digest)

    def test_dav_info(self):
        def check_metadata_fields(metadata: dict[str, Any]):
            for field in ("name", "size", "type", "last_modified", "checksums"):
                self.assertTrue(field in metadata)

        # Retrieve and check metadata details about an non-existing object
        subdir = self.tmpdir.join("inexistent", forceDirectory=True)
        metadata = subdir.info()
        check_metadata_fields(metadata)
        self.assertEqual(metadata["size"], None)
        self.assertEqual(metadata["type"], None)
        self.assertEqual(len(metadata["checksums"]), 0)
        self.assertEqual(metadata["last_modified"], datetime.min)

        # Retrieve and check metadata details about an existing directory
        subdir = self.tmpdir.join(self._get_dir_name(), forceDirectory=True)
        self.assertIsNone(subdir.mkdir())
        self.assertTrue(subdir.exists())
        metadata = subdir.info()
        check_metadata_fields(metadata)

        self.assertEqual(metadata["size"], 0)
        self.assertEqual(metadata["type"], "directory")
        self.assertEqual(len(metadata["checksums"]), 0)
        self.assertEqual(metadata["last_modified"], subdir._stat().last_modified)

        # Retrieve and check metadata details about existing file
        local_file, local_file_size = self._generate_file()
        with open(local_file, "rb") as file:
            content = file.read()
            md5_checksum = self._compute_digest(content, algorithm="md5")
            adler32_checksum = self._compute_digest(content, algorithm="adler32")

        remote_file = self.tmpdir.join("example.data")
        with open(local_file, mode="rb") as file:
            self.assertIsNone(remote_file.write(file, overwrite=True))
            self.assertEqual(os.stat(local_file).st_size, remote_file.size())

        metadata = remote_file.info()
        check_metadata_fields(metadata)
        self.assertEqual(metadata["size"], local_file_size)
        self.assertEqual(metadata["type"], "file")
        self.assertEqual(metadata["last_modified"], remote_file._stat().last_modified)

        checksums = metadata["checksums"]
        if "md5" in checksums:
            self.assertEqual(checksums["md5"], md5_checksum)
        if "adler32" in checksums:
            self.assertEqual(checksums["adler32"], adler32_checksum)

    @classmethod
    def _get_port_number(cls) -> int:
        """Return a port number the webDAV server can use to listen to."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        s.listen()
        port = s.getsockname()[1]
        s.close()
        return port

    def _serve_webdav(self, local_path: str, port: int, stop_webdav_server: Callable[[], bool]):
        """Start a local webDAV server, listening on http://localhost:port
        and exposing local_path.

        This server only runs when this test class is instantiated,
        and then shuts down. The server must be started is a separate thread.

        Parameters
        ----------
        port : `int`
            The port number on which the server should listen
        local_path : `str`
            Path to an existing local directory for the server to expose.
        stop_webdav_server : `Callable[[], bool]`
            Boolean function which returns True when the server should be
            stopped.
        """
        try:
            # Start the wsgi server in a separate thread
            config = {
                "host": "127.0.0.1",
                "port": port,
                "provider_mapping": {"/": local_path},
                "http_authenticator": {"domain_controller": None},
                "simple_dc": {"user_mapping": {"*": True}},
                "verbose": 0,
                "lock_storage": False,
                "dir_browser": {
                    "enable": False,
                    "ms_sharepoint_support": False,
                    "libre_office_support": False,
                    "response_trailer": False,
                    "davmount_links": False,
                },
            }
            server = wsgi.Server(wsgi_app=WsgiDAVApp(config), bind_addr=(config["host"], config["port"]))
            t = Thread(target=server.start, daemon=True)
            t.start()

            # Shut down the server when done: stop_webdav_server() returns
            # True when this test suite is being teared down
            while not stop_webdav_server():
                time.sleep(1)
        except KeyboardInterrupt:
            # Caught Ctrl-C, shut down the server
            pass
        finally:
            server.stop()
            t.join()

    @classmethod
    def _get_name(cls, prefix: str) -> str:
        alphabet = string.ascii_lowercase + string.digits
        return f"{prefix}-" + "".join(random.choices(alphabet, k=8))

    @classmethod
    def _get_dir_name(cls) -> str:
        """Return a randomly selected name for a file"""
        return cls._get_name(prefix="dir")

    @classmethod
    def _get_file_name(cls) -> str:
        """Return a randomly selected name for a file"""
        return cls._get_name(prefix="file")

    def _generate_file(self, remove_when_done=True) -> tuple[str, int]:
        """Create a local file of random size with random contents.

        Returns
        -------
        path : `str`
            Path to local temporary file. The caller is responsible for
            removing the file when appropriate.
        size : `int`
            Size of the generated file, in bytes.
        """
        megabyte = 1024 * 1024
        size = random.randint(2 * megabyte, 5 * megabyte)
        tmpfile, path = tempfile.mkstemp()
        self.assertEqual(os.write(tmpfile, os.urandom(size)), size)
        os.close(tmpfile)

        if remove_when_done:
            DavReadWriteTestCase.local_files_to_remove.append(path)

        return path, size

    def _make_local_temp_file(self, remove_when_done=True) -> str:
        """Create an empty local temporary file.

        Returns
        -------
        path : `str`
            Path to local temporary file. The caller is responsible for
            removing the file when appropriate.
        """
        tmpfile, path = tempfile.mkstemp()
        os.close(tmpfile)

        if remove_when_done:
            DavReadWriteTestCase.local_files_to_remove.append(path)

        return path

    @classmethod
    def _compute_digest(cls, data: bytes, algorithm: str = "sha256") -> str:
        """Compute a hash of data."""
        match algorithm:
            case "sha256" | "md5":
                m = hashlib.new(algorithm)
                m.update(data)
                return m.hexdigest().lower()
            case "adler32":
                return f"{zlib.adler32(data):08x}"
            case _:
                raise ValueError(f"unsupported checksum algorithm {algorithm}")

    @classmethod
    def _is_server_running(cls, port: int) -> bool:
        """Return True if there is a server listening on local address
        127.0.0.1:<port>.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.connect(("127.0.0.1", port))
                return True
            except ConnectionRefusedError:
                return False


class DavResourcePathConfigTestCase(unittest.TestCase):
    """Test for the DavResourcePathConfig class."""

    def setUp(self):
        # Prepare temporary directory
        self.tmpdir = ResourcePath(makeTestTempDir(TESTDIR))

        # Reinitialize globals.
        dav_globals._reset()

    def tearDown(self):
        # Clean up temporary directory
        if self.tmpdir and self.tmpdir.isLocal:
            removeTestTempDir(self.tmpdir.ospath)

        # Reinitialize globals.
        dav_globals._reset()

    def test_dav_tmpdir_buffersize_default(self):
        # Ensure that the configuration is initialized with the temporary
        # directory extracted from the environment.
        config: DavResourcePathConfig = dav_globals.config()
        tmpdir, _ = config.tmpdir_buffersize
        self.assertEqual(tmpdir, get_tempdir())


class DavConfigPoolTestCase(unittest.TestCase):
    """Test for the DavConfig class."""

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp(prefix="webdav-config-test-")

    @classmethod
    def tearDownClass(cls):
        if cls.tmpdir:
            shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def tearDown(self):
        if self.tmpdir:
            shutil.rmtree(self.tmpdir)

    def setUp(self):
        self.tmpdir = makeTestTempDir(TESTDIR)
        # Reinitialize globals.
        dav_globals._reset()

    def test_dav_default_config(self):
        """Ensure default configuration is used by default."""
        # Ensure the variable LSST_RESOURCES_WEBDAV_CONFIG is not initialized
        # so that we use the default configuration.
        with unittest.mock.patch.dict(os.environ, {}, clear=True):
            config_pool: DavConfigPool = DavConfigPool()
            config = config_pool.get_config_for_url("davs://example.org")
            self.assertEqual(config.retries, DavConfig.DEFAULT_RETRIES)
            self.assertEqual(config.timeout_connect, DavConfig.DEFAULT_TIMEOUT_CONNECT)
            self.assertEqual(config.timeout_read, DavConfig.DEFAULT_TIMEOUT_READ)
            self.assertEqual(config.token, DavConfig.DEFAULT_TOKEN)
            self.assertEqual(
                config.persistent_connections_frontend, DavConfig.DEFAULT_PERSISTENT_CONNECTIONS_FRONTEND
            )
            self.assertEqual(
                config.persistent_connections_backend, DavConfig.DEFAULT_PERSISTENT_CONNECTIONS_BACKEND
            )

    def test_dav_configuration_file_does_not_exist(self):
        # Ensure an exception is raised if the configuration file pointed to
        # by the environment variable does not exist.
        with unittest.mock.patch.dict(os.environ, {"MY_VAR": "/does/not/exist"}, clear=True):
            with self.assertRaises(FileNotFoundError):
                DavConfigPool("MY_VAR")

    def test_dav_configuration_file(self):
        """Ensure the specified configuration file is used."""
        config_contents: str = r"""
- base_url: "davs://host1.example.org:1234/"
  persistent_connections_frontend: 10
  persistent_connections_backend: 100
  timeout_connect: 20.0
  timeout_read: 120.0
  retries: 3
  retry_backoff_min: 1.0
  retry_backoff_max: 3.0
  user_cert: "${X509_USER_PROXY}"
  user_key: "${X509_USER_PROXY}"
  trusted_authorities: "/etc/grid-security/certificates"
  buffer_size: 5
  enable_fsspec: false
  collect_memory_usage: false
  request_checksum: "md5"
- base_url: "davs://host2.example.org:4321/"
  persistent_connections_frontend: 1
  persistent_connections_backend: 2
- base_url: "davs://host3.example.org:4321/"
  token: "ABCDEF"
"""

        config_file = self._create_config(config_contents)
        with unittest.mock.patch.dict(os.environ, {"LSST_RESOURCES_WEBDAV_CONFIG": config_file}, clear=True):
            config_pool: DavConfigPool = DavConfigPool("LSST_RESOURCES_WEBDAV_CONFIG")

            # Tests for base URL 'davs://host1.example.org:1234'
            config = config_pool.get_config_for_url("davs://host1.example.org:1234/any/path")
            self.assertEqual(config.base_url, "https://host1.example.org:1234/")
            self.assertEqual(config.retries, 3)
            self.assertEqual(config.token, DavConfig.DEFAULT_TOKEN)
            self.assertEqual(config.user_cert, "${X509_USER_PROXY}")
            self.assertEqual(config.trusted_authorities, "/etc/grid-security/certificates")
            self.assertFalse(config.enable_fsspec)
            self.assertFalse(config.collect_memory_usage)
            self.assertEqual(config.request_checksum, "md5")

            # Tests for base URL 'davs://host2.example.org:4321/'
            config = config_pool.get_config_for_url("davs://host2.example.org:4321")
            self.assertEqual(config.base_url, "https://host2.example.org:4321/")
            self.assertEqual(config.persistent_connections_frontend, 1)
            self.assertEqual(config.persistent_connections_backend, 2)

            # Tests for base URL 'davs://host3.example.org:4321/'
            config = config_pool.get_config_for_url("davs://host3.example.org:4321")
            self.assertEqual(config.base_url, "https://host3.example.org:4321/")
            self.assertEqual(config.token, "ABCDEF")
            self.assertEqual(config.retries, DavConfig.DEFAULT_RETRIES)

    def test_dav_repeated_configurations(self):
        """Ensure duplicated endpoint errors are detected in configuration
        file.
        """
        config_contents: str = r"""
- base_url: "davs://host1.example.org:1234/"
- base_url: "davs://host1.example.org:1234/"
"""
        config_file = self._create_config(config_contents)
        with unittest.mock.patch.dict(os.environ, {"MY_VAR": config_file}, clear=True):
            with self.assertRaises(ValueError):
                DavConfigPool("MY_VAR")

    def _create_config(self, config: str) -> str:
        with tempfile.NamedTemporaryFile(mode="wt", dir=self.tmpdir, delete=False) as f:
            f.write(config)
            return f.name


class DavTokenAuthorizerTestCase(unittest.TestCase):
    """Test for the TokenAuthorizer class."""

    def setUp(self):
        self.tmpdir = ResourcePath(makeTestTempDir(TESTDIR))
        self.token = "ABCDE1234"

    def tearDown(self):
        if self.tmpdir and self.tmpdir.isLocal:
            removeTestTempDir(self.tmpdir.ospath)

    def test_dav_empty_token(self):
        """Ensure that when no token is provided the headers are not
        modified.
        """
        authorizer = TokenAuthorizer()
        headers = {}
        authorizer.set_authorization(headers)
        self.assertIsNone(headers.get("Authorization"))

    def test_dav_token_value(self):
        """Ensure that when a token value is provided, the 'Authorization'
        header is added to the requests.
        """
        authorizer = TokenAuthorizer(self.token)
        headers = {}
        authorizer.set_authorization(headers)
        self.assertEqual(headers.get("Authorization"), f"Bearer {self.token}")

    def test_dav_token_file(self):
        """Ensure when the provided token is a file path, its contents is
        correctly added as calue of the 'Authorization' header.
        """
        with tempfile.NamedTemporaryFile(mode="wt", dir=self.tmpdir.ospath, delete=False) as f:
            f.write(self.token)
            token_file_path = f.name

        # Ensure the request's "Authorization" header is set with the right
        # token value
        os.chmod(token_file_path, stat.S_IRUSR)
        authorizer = TokenAuthorizer(token_file_path)
        headers = {}
        authorizer.set_authorization(headers)
        self.assertEqual(headers.get("Authorization"), f"Bearer {self.token}")

        # Ensure an exception is raised if either group or other can read the
        # token file
        for mode in (stat.S_IRGRP, stat.S_IWGRP, stat.S_IXGRP, stat.S_IROTH, stat.S_IWOTH, stat.S_IXOTH):
            os.chmod(token_file_path, stat.S_IRUSR | mode)
            with self.assertRaises(PermissionError):
                TokenAuthorizer(token_file_path)


if __name__ == "__main__":
    unittest.main()
