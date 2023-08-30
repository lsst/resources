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

import hashlib
import importlib
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
import warnings
from collections.abc import Callable
from threading import Thread
from typing import cast

try:
    from cheroot import wsgi
    from wsgidav.wsgidav_app import WsgiDAVApp
except ImportError:
    WsgiDAVApp = None

import lsst.resources
import requests
import responses
from lsst.resources import ResourcePath
from lsst.resources._resourceHandles._httpResourceHandle import HttpReadResourceHandle
from lsst.resources.http import (
    BearerTokenAuth,
    HttpResourcePathConfig,
    SessionStore,
    _is_protected,
    _is_webdav_endpoint,
)
from lsst.resources.tests import GenericReadWriteTestCase, GenericTestCase
from lsst.resources.utils import makeTestTempDir, removeTestTempDir

TESTDIR = os.path.abspath(os.path.dirname(__file__))


class GenericHttpTestCase(GenericTestCase, unittest.TestCase):
    """Generic tests of http URIs."""

    scheme = "http"
    netloc = "server.example"


class HttpReadWriteWebdavTestCase(GenericReadWriteTestCase, unittest.TestCase):
    """Test with a real webDAV server, as opposed to mocking responses."""

    scheme = "http"

    @classmethod
    def setUpClass(cls):
        cls.webdav_tmpdir = tempfile.mkdtemp(prefix="webdav-server-test-")
        cls.local_files_to_remove = []
        cls.server_thread = None

        # Disable warnings about socket connections left open. We purposedly
        # keep network connections to the remote server open and have no
        # means through the API exposed by Requests of actually close the
        # underlyng sockets to make tests pass without warning.
        warnings.filterwarnings(action="ignore", message=r"unclosed.*socket", category=ResourceWarning)

        # Should we test against a running server?
        #
        # This is convenient for testing against real servers in the
        # developer environment by initializing the environment variable
        # LSST_RESOURCES_HTTP_TEST_SERVER_URL with the URL of the server, e.g.
        #    https://dav.example.org:1234/path/to/top/dir
        if (test_endpoint := os.getenv("LSST_RESOURCES_HTTP_TEST_SERVER_URL")) is not None:
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

        # Reset the warnings filter.
        warnings.resetwarnings()

    def tearDown(self):
        if self.tmpdir:
            self.tmpdir.remove()

        # Clear sessions. Some sockets may be left open, because urllib3
        # doest not close in-flight connections.
        # See https://urllib3.readthedocs.io > API Reference >
        #    Pool Manager > clear()
        # I cannot add the full URL here because it is longer than 79
        # characters.
        self.tmpdir._clear_sessions()

        super().tearDown()

    def test_dav_file_handle(self):
        # Upload a new file with known contents.
        contents = "These are some \n bytes to read"
        remote_file = self.tmpdir.join(self._get_file_name())
        self.assertIsNone(remote_file.write(data=contents, overwrite=True))

        # Test that the correct handle is returned.
        with remote_file.open("rb") as handle:
            self.assertIsInstance(handle, HttpReadResourceHandle)

        # Test reading byte ranges works
        with remote_file.open("rb") as handle:
            sub_contents = contents[:10]
            handle = cast(HttpReadResourceHandle, handle)
            result = handle.read(len(sub_contents)).decode()
            self.assertEqual(result, sub_contents)
            # Verify there is no internal buffer.
            self.assertIsNone(handle._completeBuffer)
            # Verify the position.
            self.assertEqual(handle.tell(), len(sub_contents))

            # Jump back to the beginning and test if reading the whole file
            # prompts the internal buffer to be read.
            handle.seek(0)
            self.assertEqual(handle.tell(), 0)
            result = handle.read().decode()
            self.assertIsNotNone(handle._completeBuffer)
            self.assertEqual(result, contents)

            # Check that flush works on read-only handle.
            handle.flush()

        # Verify reading as a string handle works as expected.
        with remote_file.open("r") as handle:
            self.assertIsInstance(handle, io.TextIOWrapper)

            handle = cast(io.TextIOWrapper, handle)
            self.assertIsInstance(handle.buffer, HttpReadResourceHandle)

            # Check if string methods work.
            result = handle.read()
            self.assertEqual(result, contents)

            # Check that flush works on read-only handle.
            handle.flush()

        # Verify that write modes invoke the default base method
        with remote_file.open("w") as handle:
            self.assertIsInstance(handle, io.StringIO)

    def test_dav_is_dav_enpoint(self):
        # Ensure the server is a webDAV endpoint
        self.assertTrue(self.tmpdir.is_webdav_endpoint)

    def test_dav_mkdir(self):
        # Check creation and deletion of an empty directory
        subdir = self.tmpdir.join(self._get_dir_name(), forceDirectory=True)
        self.assertIsNone(subdir.mkdir())
        self.assertTrue(subdir.exists())

        # Creating an existing remote directory must succeed
        self.assertIsNone(subdir.mkdir())

        # Deletion of an existing directory must succeed
        self.assertIsNone(subdir.remove())

        # Deletion of an non-existing directory must succeed
        subir_not_exists = self.tmpdir.join(self._get_dir_name(), forceDirectory=True)
        self.assertIsNone(subir_not_exists.remove())

        # Creation of a directory at a path where a file exists must raise
        file = self.tmpdir.join(self._get_file_name(), forceDirectory=False)
        file.write(data=None, overwrite=True)
        self.assertTrue(file.exists())

        existing_file = self.tmpdir.join(file.basename(), forceDirectory=True)
        with self.assertRaises(NotADirectoryError):
            self.assertIsNone(existing_file.mkdir())

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

        local_path, is_temp = remote_file._as_local()
        self.assertTrue(is_temp)
        self.assertTrue(os.path.exists(local_path))
        self.assertTrue(os.stat(local_path).st_size, len(contents))
        self.assertEqual(ResourcePath(local_path).read(), contents)
        os.remove(local_path)

    def test_dav_size(self):
        # Size of a non-existent file must raise.
        remote_file = self.tmpdir.join(self._get_file_name())
        with self.assertRaises(FileNotFoundError):
            remote_file.size()

        # Retrieving the size of a remote directory using a file-like path must
        # raise
        remote_dir = self.tmpdir.join(self._get_dir_name(), forceDirectory=True)
        self.assertIsNone(remote_dir.mkdir())
        self.assertTrue(remote_dir.exists())

        dir_as_file = ResourcePath(remote_dir.geturl().rstrip("/"), forceDirectory=False)
        with self.assertRaises(IsADirectoryError):
            dir_as_file.size()

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
        os.remove(local_file)

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
        target_file = self.tmpdir.join(self._get_file_name())
        data = "abcdefghi"
        self.assertIsNone(target_file.write(data, overwrite=True))
        with target_file.open("rb") as handle:
            handle.seek(1)
            self.assertEqual(handle.read(4).decode("utf-8"), data[1:5])

    def test_dav_delete(self):
        # Deletion of an existing remote file must succeed
        local_file, file_size = self._generate_file()
        with open(local_file, "rb") as f:
            data = f.read()

        remote_file = self.tmpdir.join(self._get_file_name())
        self.assertIsNone(remote_file.write(data, overwrite=True))
        self.assertTrue(remote_file.exists())
        self.assertEqual(remote_file.size(), file_size)
        self.assertIsNone(remote_file.remove())
        os.remove(local_file)

        # Deletion of a non-existing remote file must succeed
        non_existing_file = self.tmpdir.join(self._get_file_name())
        self.assertIsNone(non_existing_file.remove())

        # Deletion of a non-empty remote directory must succeed
        subdir = self.tmpdir.join(self._get_dir_name(), forceDirectory=True)
        self.assertIsNone(subdir.mkdir())
        self.assertTrue(subdir.exists())
        local_file, _ = self._generate_file()
        source_file = ResourcePath(local_file)
        target_file = self.tmpdir.join(self._get_file_name(), forceDirectory=True)
        self.assertIsNone(target_file.transfer_from(source_file, transfer="copy", overwrite=True))
        self.assertIsNone(subdir.remove())
        self.assertFalse(subdir.exists())
        os.remove(local_file)

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
            self.local_files_to_remove.append(path)

        return path, size

    @classmethod
    def _compute_digest(cls, data: bytes) -> str:
        """Compute a SHA256 hash of data."""
        m = hashlib.sha256()
        m.update(data)
        return m.hexdigest()

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


class HttpResourcePathConfigTestCase(unittest.TestCase):
    """Test for the HttpResourcePathConfig class."""

    def test_send_expect_header(self):
        # Ensure environment variable LSST_HTTP_PUT_SEND_EXPECT_HEADER is
        # inspected to initialize the HttpResourcePathConfig config class.
        with unittest.mock.patch.dict(os.environ, {}, clear=True):
            importlib.reload(lsst.resources.http)
            config = HttpResourcePathConfig()
            self.assertFalse(config.send_expect_on_put)

        with unittest.mock.patch.dict(os.environ, {"LSST_HTTP_PUT_SEND_EXPECT_HEADER": "true"}, clear=True):
            importlib.reload(lsst.resources.http)
            config = HttpResourcePathConfig()
            self.assertTrue(config.send_expect_on_put)

    def test_collect_memory_usage(self):
        # Ensure environment variable LSST_HTTP_COLLECT_MEMORY_USAGE is
        # inspected to initialize the HttpResourcePathConfig class.
        with unittest.mock.patch.dict(os.environ, {}, clear=True):
            importlib.reload(lsst.resources.http)
            config = HttpResourcePathConfig()
            self.assertFalse(config.collect_memory_usage)

        with unittest.mock.patch.dict(os.environ, {"LSST_HTTP_COLLECT_MEMORY_USAGE": "true"}, clear=True):
            importlib.reload(lsst.resources.http)
            config = HttpResourcePathConfig()
            self.assertTrue(config.collect_memory_usage)

    def test_timeout(self):
        # Ensure that when the connect and read timeouts are not specified
        # the default values are stored in the config.
        with unittest.mock.patch.dict(os.environ, {}, clear=True):
            importlib.reload(lsst.resources.http)
            config = HttpResourcePathConfig()
            self.assertAlmostEqual(config.timeout[0], config.DEFAULT_TIMEOUT_CONNECT)
            self.assertAlmostEqual(config.timeout[1], config.DEFAULT_TIMEOUT_READ)

        # Ensure that when both the connect and read timeouts are specified
        # they are both stored in the config.
        connect_timeout, read_timeout = 100.5, 200.8
        with unittest.mock.patch.dict(
            os.environ,
            {"LSST_HTTP_TIMEOUT_CONNECT": str(connect_timeout), "LSST_HTTP_TIMEOUT_READ": str(read_timeout)},
            clear=True,
        ):
            # Force module reload.
            importlib.reload(lsst.resources.http)
            config = HttpResourcePathConfig()
            self.assertAlmostEqual(config.timeout[0], connect_timeout)
            self.assertAlmostEqual(config.timeout[1], read_timeout)

        # Ensure that invalid float values (including NaN values) raise a
        # ValueError.
        for value in ("invalid", "NaN"):
            with unittest.mock.patch.dict(
                os.environ,
                {"LSST_HTTP_TIMEOUT_CONNECT": value, "LSST_HTTP_TIMEOUT_READ": value},
                clear=True,
            ):
                # Force module reload.
                importlib.reload(lsst.resources.http)
                with self.assertRaises(ValueError):
                    config = HttpResourcePathConfig()
                    config.timeout()

    def test_front_end_connections(self):
        # Ensure that when the number of front end connections is not specified
        # the default is stored in the config.
        with unittest.mock.patch.dict(os.environ, {}, clear=True):
            importlib.reload(lsst.resources.http)
            config = HttpResourcePathConfig()
            self.assertEqual(config.front_end_connections, config.DEFAULT_FRONTEND_PERSISTENT_CONNECTIONS)

        # Ensure that when the number of front end connections is specified
        # it is stored in the config.
        connections = 42
        with unittest.mock.patch.dict(
            os.environ, {"LSST_HTTP_FRONTEND_PERSISTENT_CONNECTIONS": str(connections)}, clear=True
        ):
            importlib.reload(lsst.resources.http)
            config = HttpResourcePathConfig()
            self.assertTrue(config.front_end_connections, connections)

    def test_back_end_connections(self):
        # Ensure that when the number of back end connections is not specified
        # the default is stored in the config.
        with unittest.mock.patch.dict(os.environ, {}, clear=True):
            importlib.reload(lsst.resources.http)
            config = HttpResourcePathConfig()
            self.assertEqual(config.back_end_connections, config.DEFAULT_BACKEND_PERSISTENT_CONNECTIONS)

        # Ensure that when the number of back end connections is specified
        # it is stored in the config.
        connections = 42
        with unittest.mock.patch.dict(
            os.environ, {"LSST_HTTP_BACKEND_PERSISTENT_CONNECTIONS": str(connections)}, clear=True
        ):
            importlib.reload(lsst.resources.http)
            config = HttpResourcePathConfig()
            self.assertTrue(config.back_end_connections, connections)

    def test_digest_algorithm(self):
        # Ensure that when no digest is specified in the environment, the
        # configured digest algorithm is the empty string.
        with unittest.mock.patch.dict(os.environ, {}, clear=True):
            importlib.reload(lsst.resources.http)
            config = HttpResourcePathConfig()
            self.assertEqual(config.digest_algorithm, "")

        # Ensure that an invalid digest algorithm is ignored.
        digest = "invalid"
        with unittest.mock.patch.dict(os.environ, {"LSST_HTTP_DIGEST": digest}, clear=True):
            importlib.reload(lsst.resources.http)
            config = HttpResourcePathConfig()
            self.assertEqual(config.digest_algorithm, "")

        # Ensure that an accepted digest algorithm is stored.
        for digest in HttpResourcePathConfig().ACCEPTED_DIGESTS:
            with unittest.mock.patch.dict(os.environ, {"LSST_HTTP_DIGEST": digest}, clear=True):
                importlib.reload(lsst.resources.http)
                config = HttpResourcePathConfig()
                self.assertTrue(config.digest_algorithm, digest)

    def test_backoff_interval(self):
        # Ensure that when no backoff interval is defined, the default values
        # are used.
        with unittest.mock.patch.dict(os.environ, {}, clear=True):
            importlib.reload(lsst.resources.http)
            config = HttpResourcePathConfig()
            self.assertAlmostEqual(config.backoff_min, config.DEFAULT_BACKOFF_MIN)
            self.assertAlmostEqual(config.backoff_max, config.DEFAULT_BACKOFF_MAX)

        # Ensure that an invalid value for backoff interval is ignored and
        # the default value is used.
        with unittest.mock.patch.dict(
            os.environ, {"LSST_HTTP_BACKOFF_MIN": "XXX", "LSST_HTTP_BACKOFF_MAX": "YYY"}, clear=True
        ):
            importlib.reload(lsst.resources.http)
            config = HttpResourcePathConfig()
            self.assertAlmostEqual(config.backoff_min, config.DEFAULT_BACKOFF_MIN)
            self.assertAlmostEqual(config.backoff_max, config.DEFAULT_BACKOFF_MAX)

        # Ensure that NaN values are ignored and the defaults values are used.
        with unittest.mock.patch.dict(
            os.environ, {"LSST_HTTP_BACKOFF_MIN": "NaN", "LSST_HTTP_BACKOFF_MAX": "NaN"}, clear=True
        ):
            importlib.reload(lsst.resources.http)
            config = HttpResourcePathConfig()
            self.assertAlmostEqual(config.backoff_min, config.DEFAULT_BACKOFF_MIN)
            self.assertAlmostEqual(config.backoff_max, config.DEFAULT_BACKOFF_MAX)

        # Ensure that when specified, valid limits backoff interval are used.
        backoff_min, backoff_max = 3.0, 8.0
        with unittest.mock.patch.dict(
            os.environ,
            {"LSST_HTTP_BACKOFF_MIN": str(backoff_min), "LSST_HTTP_BACKOFF_MAX": str(backoff_max)},
            clear=True,
        ):
            importlib.reload(lsst.resources.http)
            config = HttpResourcePathConfig()
            self.assertAlmostEqual(config.backoff_min, backoff_min)
            self.assertAlmostEqual(config.backoff_max, backoff_max)


class WebdavUtilsTestCase(unittest.TestCase):
    """Test for the Webdav related utilities."""

    def setUp(self):
        self.tmpdir = ResourcePath(makeTestTempDir(TESTDIR))

    def tearDown(self):
        if self.tmpdir and self.tmpdir.isLocal:
            removeTestTempDir(self.tmpdir.ospath)

    @responses.activate
    def test_is_webdav_endpoint(self):
        davEndpoint = "http://www.lsstwithwebdav.org"
        responses.add(responses.OPTIONS, davEndpoint, status=200, headers={"DAV": "1,2,3"})
        self.assertTrue(_is_webdav_endpoint(davEndpoint))

        plainHttpEndpoint = "http://www.lsstwithoutwebdav.org"
        responses.add(responses.OPTIONS, plainHttpEndpoint, status=200)
        self.assertFalse(_is_webdav_endpoint(plainHttpEndpoint))

        notWebdavEndpoint = "http://www.notwebdav.org"
        responses.add(responses.OPTIONS, notWebdavEndpoint, status=403)
        self.assertFalse(_is_webdav_endpoint(notWebdavEndpoint))

    def test_is_protected(self):
        self.assertFalse(_is_protected("/this-file-does-not-exist"))

        with tempfile.NamedTemporaryFile(mode="wt", dir=self.tmpdir.ospath, delete=False) as f:
            f.write("XXXX")
            file_path = f.name

        os.chmod(file_path, stat.S_IRUSR)
        self.assertTrue(_is_protected(file_path))

        for mode in (stat.S_IRGRP, stat.S_IWGRP, stat.S_IXGRP, stat.S_IROTH, stat.S_IWOTH, stat.S_IXOTH):
            os.chmod(file_path, stat.S_IRUSR | mode)
            self.assertFalse(_is_protected(file_path))


class BearerTokenAuthTestCase(unittest.TestCase):
    """Test for the BearerTokenAuth class."""

    def setUp(self):
        self.tmpdir = ResourcePath(makeTestTempDir(TESTDIR))
        self.token = "ABCDE1234"

    def tearDown(self):
        if self.tmpdir and self.tmpdir.isLocal:
            removeTestTempDir(self.tmpdir.ospath)

    def test_empty_token(self):
        """Ensure that when no token is provided the request is not
        modified.
        """
        auth = BearerTokenAuth(None)
        auth._refresh()
        self.assertIsNone(auth._token)
        self.assertIsNone(auth._path)
        req = requests.Request("GET", "https://example.org")
        self.assertEqual(auth(req), req)

    def test_token_value(self):
        """Ensure that when a token value is provided, the 'Authorization'
        header is added to the requests.
        """
        auth = BearerTokenAuth(self.token)
        req = auth(requests.Request("GET", "https://example.org").prepare())
        self.assertEqual(req.headers.get("Authorization"), f"Bearer {self.token}")

    def test_token_insecure_http(self):
        """Ensure that no 'Authorization' header is attached to a request when
        using insecure HTTP.
        """
        auth = BearerTokenAuth(self.token)
        for url in ("http://example.org", "HTTP://example.org", "HttP://example.org"):
            req = auth(requests.Request("GET", url).prepare())
            self.assertIsNone(req.headers.get("Authorization"))

    def test_token_file(self):
        """Ensure when the provided token is a file path, its contents is
        correctly used in the the 'Authorization' header of the requests.
        """
        with tempfile.NamedTemporaryFile(mode="wt", dir=self.tmpdir.ospath, delete=False) as f:
            f.write(self.token)
            token_file_path = f.name

        # Ensure the request's "Authorization" header is set with the right
        # token value
        os.chmod(token_file_path, stat.S_IRUSR)
        auth = BearerTokenAuth(token_file_path)
        req = auth(requests.Request("GET", "https://example.org").prepare())
        self.assertEqual(req.headers.get("Authorization"), f"Bearer {self.token}")

        # Ensure an exception is raised if either group or other can read the
        # token file
        for mode in (stat.S_IRGRP, stat.S_IWGRP, stat.S_IXGRP, stat.S_IROTH, stat.S_IWOTH, stat.S_IXOTH):
            os.chmod(token_file_path, stat.S_IRUSR | mode)
            with self.assertRaises(PermissionError):
                BearerTokenAuth(token_file_path)


class SessionStoreTestCase(unittest.TestCase):
    """Test for the SessionStore class."""

    def setUp(self):
        self.tmpdir = ResourcePath(makeTestTempDir(TESTDIR))
        self.rpath = ResourcePath("https://example.org")

    def tearDown(self):
        if self.tmpdir and self.tmpdir.isLocal:
            removeTestTempDir(self.tmpdir.ospath)

    def test_ca_cert_bundle(self):
        """Ensure a certificate authorities bundle is used to authentify
        the remote server.
        """
        with tempfile.NamedTemporaryFile(mode="wt", dir=self.tmpdir.ospath, delete=False) as f:
            f.write("CERT BUNDLE")
            cert_bundle = f.name

        with unittest.mock.patch.dict(os.environ, {"LSST_HTTP_CACERT_BUNDLE": cert_bundle}, clear=True):
            session = SessionStore().get(self.rpath)
            self.assertEqual(session.verify, cert_bundle)

    def test_user_cert(self):
        """Ensure if user certificate and private key are provided, they are
        used for authenticating the client.
        """
        # Create mock certificate and private key files.
        with tempfile.NamedTemporaryFile(mode="wt", dir=self.tmpdir.ospath, delete=False) as f:
            f.write("CERT")
            client_cert = f.name

        with tempfile.NamedTemporaryFile(mode="wt", dir=self.tmpdir.ospath, delete=False) as f:
            f.write("KEY")
            client_key = f.name

        # Check both LSST_HTTP_AUTH_CLIENT_CERT and LSST_HTTP_AUTH_CLIENT_KEY
        # must be initialized.
        with unittest.mock.patch.dict(os.environ, {"LSST_HTTP_AUTH_CLIENT_CERT": client_cert}, clear=True):
            with self.assertRaises(ValueError):
                SessionStore().get(self.rpath)

        with unittest.mock.patch.dict(os.environ, {"LSST_HTTP_AUTH_CLIENT_KEY": client_key}, clear=True):
            with self.assertRaises(ValueError):
                SessionStore().get(self.rpath)

        # Check private key file must be accessible only by its owner.
        with unittest.mock.patch.dict(
            os.environ,
            {"LSST_HTTP_AUTH_CLIENT_CERT": client_cert, "LSST_HTTP_AUTH_CLIENT_KEY": client_key},
            clear=True,
        ):
            # Ensure the session client certificate is initialized when
            # only the owner can read the private key file.
            os.chmod(client_key, stat.S_IRUSR)
            session = SessionStore().get(self.rpath)
            self.assertEqual(session.cert[0], client_cert)
            self.assertEqual(session.cert[1], client_key)

            # Ensure an exception is raised if either group or other can access
            # the private key file.
            for mode in (stat.S_IRGRP, stat.S_IWGRP, stat.S_IXGRP, stat.S_IROTH, stat.S_IWOTH, stat.S_IXOTH):
                os.chmod(client_key, stat.S_IRUSR | mode)
                with self.assertRaises(PermissionError):
                    SessionStore().get(self.rpath)

    def test_token_env(self):
        """Ensure when the token is provided via an environment variable
        the sessions are equipped with a BearerTokenAuth.
        """
        token = "ABCDE"
        with unittest.mock.patch.dict(os.environ, {"LSST_HTTP_AUTH_BEARER_TOKEN": token}, clear=True):
            session = SessionStore().get(self.rpath)
            self.assertEqual(type(session.auth), lsst.resources.http.BearerTokenAuth)
            self.assertEqual(session.auth._token, token)
            self.assertIsNone(session.auth._path)

    def test_sessions(self):
        """Ensure the session caching mechanism works."""
        # Ensure the store provides a session for a given URL
        root_url = "https://example.org"
        store = SessionStore()
        session = store.get(ResourcePath(root_url))
        self.assertIsNotNone(session)

        # Ensure the sessions retrieved from a single store with the same
        # root URIs are equal
        for u in (f"{root_url}", f"{root_url}/path/to/file"):
            self.assertEqual(session, store.get(ResourcePath(u)))

        # Ensure sessions retrieved for different root URIs are different
        another_url = "https://another.example.org"
        self.assertNotEqual(session, store.get(ResourcePath(another_url)))

        # Ensure the sessions retrieved from a single store for URLs with
        # different port numbers are different
        root_url_with_port = f"{another_url}:12345"
        session = store.get(ResourcePath(root_url_with_port))
        self.assertNotEqual(session, store.get(ResourcePath(another_url)))

        # Ensure the sessions retrieved from a single store with the same
        # root URIs (including port numbers) are equal
        for u in (f"{root_url_with_port}", f"{root_url_with_port}/path/to/file"):
            self.assertEqual(session, store.get(ResourcePath(u)))


if __name__ == "__main__":
    unittest.main()
