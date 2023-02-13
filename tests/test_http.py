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
from threading import Thread
from typing import Callable, Tuple, cast

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
from lsst.resources.http import BearerTokenAuth, SessionStore, _is_protected, _is_webdav_endpoint
from lsst.resources.tests import GenericReadWriteTestCase, GenericTestCase
from lsst.resources.utils import makeTestTempDir, removeTestTempDir

TESTDIR = os.path.abspath(os.path.dirname(__file__))


class GenericHttpTestCase(GenericTestCase, unittest.TestCase):
    scheme = "http"
    netloc = "server.example"


# TODO: this test case should be removed once HttpResourcePath supports
# walk() and we can fully test that GenericTestCase passes against a
# real webDAV server. For the time being we skip it because mocking
# all the possible responses for every possible situation is tedious.
@unittest.skipIf(True, "Skipping test with mocked responses.")
class HttpReadWriteTestCase(unittest.TestCase):
    """Specialist test cases for WebDAV server.

    The responses class requires that every possible request be explicitly
    mocked out.  This currently makes it extremely inconvenient to subclass
    the generic read/write tests shared by other URI schemes.  For now use
    explicit standalone tests.
    """

    def setUp(self):
        # Local test directory
        self.tmpdir = ResourcePath(makeTestTempDir(TESTDIR))

        existingFolderName = "existingFolder"
        notExistingFolderName = "notExistingFolder"
        existingFileName = "existingFile"
        notExistingFileName = "notExistingFile"

        # DAV endpoint resources
        self.davEndpoint = "http://dav.not-exists.org"
        responses.add(
            responses.OPTIONS,
            self.davEndpoint,
            status=200,
            headers={"DAV": "1,2,3"},
            auto_calculate_content_length=True,
        )

        # DAV existing folder and its parent directory
        self.davExistingFolderResource = ResourcePath(
            f"{self.davEndpoint}/{existingFolderName}", forceDirectory=True
        )
        body = f"""
        <?xml version="1.0" encoding="UTF-8"?>
        <D:multistatus xmlns:D="DAV:">
            <D:response>
                <D:href>{self.davExistingFolderResource.relativeToPathRoot}</D:href>
                <D:propstat>
                    <D:prop>
                        <D:resourcetype>
                            <D:collection xmlns:D="DAV:"/>
                        </D:resourcetype>
                        <D:getlastmodified>Fri, 27 Jan 2 023 13:59:01 GMT</D:getlastmodified>
                    </D:prop>
                    <D:status>HTTP/1.1 200 OK</D:status>
                </D:propstat>
            </D:response>
        </D:multistatus>
        """
        responses.add(
            "PROPFIND",
            self.davExistingFolderResource.geturl(),
            body=body,
            status=requests.codes.multi_status,
            content_type="text/xml; charset=utf-8",
            auto_calculate_content_length=True,
        )

        href = self.davExistingFolderResource.parent().relativeToPathRoot
        href = "/" if href in (".", "./") else href
        body = f"""
        <?xml version="1.0" encoding="UTF-8"?>
        <D:multistatus xmlns:D="DAV:">
            <D:response>
                <D:href>{href}</D:href>
                <D:propstat>
                    <D:prop>
                        <D:resourcetype>
                            <D:collection xmlns:D="DAV:"/>
                        </D:resourcetype>
                        <D:getlastmodified>Fri, 27 Jan 2 023 13:59:01 GMT</D:getlastmodified>
                    </D:prop>
                    <D:status>HTTP/1.1 200 OK</D:status>
                </D:propstat>
            </D:response>
        </D:multistatus>
        """
        responses.add(
            "PROPFIND",
            self.davExistingFolderResource.parent().geturl(),
            body=body,
            status=requests.codes.multi_status,
            content_type="text/xml; charset=utf-8",
            auto_calculate_content_length=True,
        )

        # DAV existing file.
        self.davExistingFileResource = ResourcePath(
            f"{self.davEndpoint}/{existingFolderName}/{existingFileName}"
        )
        self.davExistingFileSize = 1024
        body = f"""
        <?xml version="1.0" encoding="UTF-8"?>
        <D:multistatus xmlns:D="DAV:">
            <D:response><D:href>{self.davExistingFileResource.relativeToPathRoot}</D:href>
                <D:propstat>
                    <D:prop>
                        <D:getlastmodified>Fri, 27 Jan 2023 13:05:16 GMT</D:getlastmodified>
                        <D:getcontentlength>{self.davExistingFileSize}</D:getcontentlength>
                    </D:prop>
                    <D:status>HTTP/1.1 200 OK</D:status>
                </D:propstat>
            </D:response>
        </D:multistatus>
        """
        responses.add(
            "PROPFIND",
            self.davExistingFileResource.geturl(),
            body=body,
            status=requests.codes.multi_status,
            content_type="text/xml; charset=utf-8",
            auto_calculate_content_length=True,
        )

        # DAV not existing file.
        self.davNotExistingFileResource = ResourcePath(
            f"{self.davEndpoint}/{existingFolderName}/{notExistingFileName}"
        )
        responses.add(
            "PROPFIND",
            self.davNotExistingFileResource.geturl(),
            body="Not Found",
            status=requests.codes.not_found,
            content_type="text/plain; charset=utf-8",
            auto_calculate_content_length=True,
        )

        # DAV not existing folder.
        self.davNotExistingFolderResource = ResourcePath(
            f"{self.davEndpoint}/{notExistingFolderName}", forceDirectory=True
        )
        responses.add(
            "PROPFIND",
            self.davNotExistingFolderResource.geturl(),
            body="Not Found",
            status=requests.codes.not_found,
            content_type="text/plain; charset=utf-8",
            auto_calculate_content_length=True,
        )

        # Plain HTTP endpoint resources.
        self.plainHttpEndpoint = "http://plain.not-exists.org"
        responses.add(
            responses.OPTIONS,
            self.plainHttpEndpoint,
            status=200,
            headers={"Allow": "POST,OPTIONS,GET,HEAD,TRACE"},
            auto_calculate_content_length=True,
        )

        # Plain HTTP existing folder and existing file.
        self.plainExistingFolderResource = ResourcePath(
            f"{self.plainHttpEndpoint}/{existingFolderName}", forceDirectory=True
        )

        self.plainExistingFileResource = ResourcePath(
            f"{self.plainHttpEndpoint}/{existingFolderName}/{existingFileName}"
        )
        self.plainExistingFileSize = 1024
        responses.add(
            responses.HEAD,
            self.plainExistingFileResource.geturl(),
            status=requests.codes.ok,
            headers={"Content-Length": f"{self.plainExistingFileSize}"},
        )

        # Plain HTTP not existing file.
        self.plainNotExistingFileResource = ResourcePath(
            f"{self.plainHttpEndpoint}/{existingFolderName}/{notExistingFileName}"
        )
        responses.add(
            responses.HEAD,
            self.plainNotExistingFileResource.geturl(),
            status=requests.codes.not_found,
        )

        # Resources for file handle tests.
        self.handleWithRangeResourcePath = ResourcePath(
            f"{self.plainHttpEndpoint}/{existingFolderName}/handleWithRange"
        )
        self.handleWithOutRangeResourcePath = ResourcePath(
            f"{self.plainHttpEndpoint}/{existingFolderName}/handleWithOutRange"
        )

    def tearDown(self):
        if self.tmpdir:
            if self.tmpdir.isLocal:
                removeTestTempDir(self.tmpdir.ospath)

    @responses.activate
    def test_file_handle(self):
        responses.add(
            responses.HEAD,
            self.handleWithRangeResourcePath.geturl(),
            status=requests.codes.ok,
            headers={"Content-Length": "1024", "Accept-Ranges": "true"},
        )
        handleWithRangeBody = "These are some \n bytes to read"
        responses.add(
            responses.GET,
            self.handleWithRangeResourcePath.geturl(),
            status=requests.codes.partial_content,  # 206
            body=handleWithRangeBody.encode(),
        )
        responses.add(
            responses.PUT,
            self.handleWithRangeResourcePath.geturl(),
            status=requests.codes.created,  # 201
        )

        responses.add(
            responses.HEAD,
            self.handleWithOutRangeResourcePath.geturl(),
            status=requests.codes.ok,  # 200
            headers={"Content-Length": "1024"},
        )
        responses.add(
            responses.GET,
            self.handleWithOutRangeResourcePath.geturl(),
            status=requests.codes.ok,  # 200
            body="These are some bytes to read".encode(),
        )

        # Test that without the correct header the default method is used.
        with self.handleWithOutRangeResourcePath.open("rb") as handle:
            self.assertIsInstance(handle, io.BytesIO)

        # Test that with correct header the correct handle is returned.
        with self.handleWithRangeResourcePath.open("rb") as handle:
            self.assertIsInstance(handle, HttpReadResourceHandle)

        # Test reading byte ranges works
        with self.handleWithRangeResourcePath.open("rb") as handle:
            handle = cast(HttpReadResourceHandle, handle)
            # This is not a real test, because responses can not actually
            # handle reading sub byte ranges, so the whole thing needs to be
            # read.
            result = handle.read(len(handleWithRangeBody)).decode()
            self.assertEqual(result, handleWithRangeBody)
            # Verify there is no internal buffer.
            self.assertIsNone(handle._completeBuffer)
            # Verify the position.
            self.assertEqual(handle.tell(), len(handleWithRangeBody))

            # Jump back to the beginning and test if reading the whole file
            # prompts the internal buffer to be read.
            handle.seek(0)
            self.assertEqual(handle.tell(), 0)
            result = handle.read().decode()
            self.assertIsNotNone(handle._completeBuffer)
            self.assertEqual(result, handleWithRangeBody)

        # Verify reading as a string handle works as expected.
        with self.handleWithRangeResourcePath.open("r") as handle:
            self.assertIsInstance(handle, io.TextIOWrapper)

            handle = cast(io.TextIOWrapper, handle)
            self.assertIsInstance(handle.buffer, HttpReadResourceHandle)

            # Check if string methods work.
            result = handle.read()
            self.assertEqual(result, handleWithRangeBody)

        # Verify that write modes invoke the default base method
        with self.handleWithRangeResourcePath.open("w") as handle:
            self.assertIsInstance(handle, io.StringIO)

    @responses.activate
    def test_exists_dav(self):
        # Existing file
        self.assertTrue(self.davExistingFileResource.exists())

        # Not existing file
        self.assertFalse(self.davNotExistingFileResource.exists())

    @responses.activate
    def test_exists_plain(self):
        # Existing file
        self.assertTrue(self.plainExistingFileResource.exists())

        # Not existing file
        self.assertFalse(self.plainNotExistingFileResource.exists())

    @responses.activate
    def test_mkdir_dav(self):
        # Test we cannot create a directory from a non-directory like resource
        # path.
        with self.assertRaises(NotADirectoryError):
            self.davNotExistingFileResource.mkdir()

        # Test we can successfully create a non-existing directory.
        responses.add(
            "MKCOL",
            self.davNotExistingFolderResource.geturl(),
            body="Created",
            status=requests.codes.created,
            content_type="text/plain; charset=utf-8",
            auto_calculate_content_length=True,
        )
        self.davNotExistingFolderResource.mkdir()

        # Test that creation of a existing directory works.
        self.davExistingFolderResource.mkdir()

    @responses.activate
    def test_mkdir_plain(self):
        # Ensure creation of directories on plain HTTP servers raises.
        with self.assertRaises(NotImplementedError):
            self.plainExistingFileResource.mkdir()

    def test_parent(self):
        self.assertEqual(
            self.davExistingFolderResource.geturl(), self.davNotExistingFileResource.parent().geturl()
        )

        baseURL = ResourcePath(self.davEndpoint, forceDirectory=True)
        self.assertEqual(baseURL.geturl(), baseURL.parent().geturl())

        self.assertEqual(
            self.davExistingFileResource.parent().geturl(), self.davExistingFileResource.dirname().geturl()
        )

    @responses.activate
    def test_read(self):
        # Test read of an existing file works.
        body = str.encode("It works!")
        responses.add(
            responses.GET, self.davExistingFileResource.geturl(), status=requests.codes.ok, body=body
        )
        self.assertEqual(self.davExistingFileResource.read().decode(), body.decode())

        # Test read of a not existing file raises.
        responses.add(
            responses.GET, self.davNotExistingFileResource.geturl(), status=requests.codes.not_found
        )
        with self.assertRaises(FileNotFoundError):
            self.davNotExistingFileResource.read()

        # Run this twice to ensure use of cache in code coverage.
        for _ in (1, 2):
            with self.davExistingFileResource.as_local() as local_uri:
                self.assertTrue(local_uri.isLocal)
                content = local_uri.read().decode()
                self.assertEqual(content, body.decode())

        # Check that the environment variable LSST_RESOURCES_TMPDIR is being
        # read.
        saved_tmpdir = lsst.resources.http._TMPDIR
        lsst.resources.http._TMPDIR = None
        with unittest.mock.patch.dict(os.environ, {"LSST_RESOURCES_TMPDIR": self.tmpdir.ospath}):
            with self.davExistingFileResource.as_local() as local_uri:
                self.assertTrue(local_uri.isLocal)
                content = local_uri.read().decode()
                self.assertEqual(content, body.decode())
                self.assertIsNotNone(local_uri.relative_to(self.tmpdir))

        # Restore original _TMPDIR to avoid issues related to the execution
        # order of tests
        lsst.resources.http._TMPDIR = saved_tmpdir

    @responses.activate
    def test_as_local(self):
        remote_path = self.davExistingFolderResource.join("test-as-local")
        body = str.encode("12345")
        responses.add(
            responses.GET,
            remote_path.geturl(),
            status=requests.codes.ok,
            body=body,
            auto_calculate_content_length=True,
        )
        local_path, is_temp = remote_path._as_local()
        self.assertTrue(is_temp)
        self.assertTrue(os.path.exists(local_path))
        self.assertEqual(ResourcePath(local_path).read(), body)

    @responses.activate
    def test_remove_dav(self):
        # Test deletion of an existing file.
        responses.add(responses.DELETE, self.davExistingFileResource.geturl(), status=requests.codes.ok)
        self.assertIsNone(self.davExistingFileResource.remove())

        # Test deletion of a non-existing file.
        responses.add(
            responses.DELETE, self.davNotExistingFileResource.geturl(), status=requests.codes.not_found
        )
        with self.assertRaises(FileNotFoundError):
            self.davNotExistingFileResource.remove()

    @responses.activate
    def test_remove_plain(self):
        # Test deletion of an existing file.
        responses.add(responses.DELETE, self.plainExistingFileResource.geturl(), status=requests.codes.ok)
        self.assertIsNone(self.plainExistingFileResource.remove())

        # Test deletion of a non-existing file.
        responses.add(
            responses.DELETE, self.plainNotExistingFileResource.geturl(), status=requests.codes.not_found
        )
        with self.assertRaises(FileNotFoundError):
            self.plainNotExistingFileResource.remove()

        # Deletion of a directory must raise
        with self.assertRaises(NotImplementedError):
            self.plainExistingFolderResource.remove()

    @responses.activate
    def test_size_dav(self):
        # Existing file
        self.assertEqual(self.davExistingFileResource.size(), self.davExistingFileSize)

        # Not existing file
        with self.assertRaises(FileNotFoundError):
            self.davNotExistingFileResource.size()

    @responses.activate
    def test_size_plain(self):
        # Existing file
        self.assertEqual(self.plainExistingFileResource.size(), self.plainExistingFileSize)

        # Not existing file
        with self.assertRaises(FileNotFoundError):
            self.plainNotExistingFileResource.size()

    @responses.activate
    def test_transfer_dav(self):
        # Transferring with an invalid transfer mode must raise.
        with self.assertRaises(ValueError):
            self.davNotExistingFileResource.transfer_from(
                src=self.davExistingFileResource, transfer="unsupported"
            )

        # Transferring to self should be no-op.
        self.assertIsNone(self.davExistingFileResource.transfer_from(src=self.davExistingFileResource))

        # Transferring to an existing file without overwrite must raise.
        with self.assertRaises(FileExistsError):
            self.davExistingFileResource.transfer_from(src=self.davNotExistingFileResource, overwrite=False)

        # Transfer in "copy" or "auto" mode: we need to mock two responses.
        # One using "COPY" and one using "GET", to turn around the issue when
        # the DAV server does not correctly implement "COPY" and the client
        # uses "GET" and then "PUT".
        responses.add(
            "COPY",
            self.davExistingFileResource.geturl(),
            body="Created",
            status=requests.codes.created,
            content_type="text/plain; charset=utf-8",
            auto_calculate_content_length=True,
            match=[
                responses.matchers.header_matcher({"Destination": self.davNotExistingFileResource.geturl()})
            ],
        )
        body = str.encode("12345")
        responses.add(
            responses.GET,
            self.davExistingFileResource.geturl(),
            status=requests.codes.ok,
            body=body,
            auto_calculate_content_length=True,
        )
        responses.add(responses.PUT, self.davNotExistingFileResource.geturl(), status=requests.codes.created)
        self.assertIsNone(
            self.davNotExistingFileResource.transfer_from(src=self.davExistingFileResource, transfer="auto")
        )

        # Transfer in "move" mode.
        responses.add(
            "MOVE",
            self.davExistingFileResource.geturl(),
            body="Created",
            status=requests.codes.created,
            content_type="text/plain; charset=utf-8",
            auto_calculate_content_length=True,
            match=[
                responses.matchers.header_matcher({"Destination": self.davNotExistingFileResource.geturl()})
            ],
        )
        self.assertIsNone(
            self.davNotExistingFileResource.transfer_from(src=self.davExistingFileResource, transfer="move")
        )

        # Transfer from local file to DAV server must succeed.
        content = "0123456"
        local_file = self.tmpdir.join("test-local")
        local_file.write(content.encode())
        responses.add(responses.PUT, self.davNotExistingFileResource.geturl(), status=requests.codes.created)
        self.assertIsNone(self.davNotExistingFileResource.transfer_from(src=local_file))

    @responses.activate
    def test_transfer_plain(self):
        # Transferring with an invalid mode must raise.
        with self.assertRaises(ValueError):
            self.plainNotExistingFileResource.transfer_from(
                src=self.plainExistingFileResource, transfer="unsupported"
            )

        # Transferring to self should be no-op.
        self.assertIsNone(self.plainExistingFileResource.transfer_from(src=self.plainExistingFileResource))

        # Transferring to an existing file without overwrite must raise.
        with self.assertRaises(FileExistsError):
            self.plainExistingFileResource.transfer_from(
                src=self.plainNotExistingFileResource, overwrite=False
            )

        # Transfer from plain HTTP server to plain HTTP server must succeed.
        content = "0123456".encode()
        responses.add(
            responses.GET,
            self.plainExistingFileResource.geturl(),
            status=requests.codes.ok,
            body=content,
            auto_calculate_content_length=True,
        )
        responses.add(
            responses.GET, self.plainNotExistingFileResource.geturl(), status=requests.codes.created
        )
        responses.add(
            responses.PUT, self.plainNotExistingFileResource.geturl(), status=requests.codes.created
        )
        self.assertIsNone(self.plainNotExistingFileResource.transfer_from(src=self.plainExistingFileResource))

        # Transfer from local file to plain HTTP server must succeed.
        local_file = self.tmpdir.join("test-local")
        local_file.write(content)
        self.assertIsNone(self.plainNotExistingFileResource.transfer_from(src=local_file))

    @responses.activate
    def test_write(self):
        # Test write an existing file without overwrite raises.
        data = str.encode("Some content.")
        with self.assertRaises(FileExistsError):
            self.davExistingFileResource.write(data=data, overwrite=False)

        # Test write succeeds.
        path = ResourcePath(f"{self.davEndpoint}/put")
        responses.add(responses.PUT, path.geturl(), status=requests.codes.created)
        self.assertIsNone(path.write(data=data))

        # Test a server error response raises.
        path = ResourcePath(f"{self.davEndpoint}/put-error")
        responses.add(responses.PUT, path.geturl(), status=requests.codes.not_found)
        with self.assertRaises(ValueError):
            path.write(data=data)

        # Test write with redirection succeeds.
        os.environ.pop("LSST_HTTP_PUT_SEND_EXPECT_HEADER", None)
        importlib.reload(lsst.resources.http)

        path_redirect = ResourcePath(f"{self.davEndpoint}/redirect/file")
        redirected_url = f"{self.davEndpoint}/redirect/location"
        responses.add(
            responses.PUT,
            path_redirect.geturl(),
            headers={"Location": redirected_url},
            status=requests.codes.temporary_redirect,
        )
        responses.add(responses.PUT, redirected_url, status=requests.codes.ok)
        self.assertIsNone(path_redirect.write(data=data))

        # Test write with redirection and using Expect header succeeds.
        path_expect = ResourcePath(f"{self.davEndpoint}/redirect-expect/file")
        redirected_url = f"{self.davEndpoint}/redirect-expect/location"
        responses.add(
            responses.PUT,
            path_expect.geturl(),
            headers={"Location": redirected_url},
            status=requests.codes.temporary_redirect,
            match=[responses.matchers.header_matcher({"Content-Length": "0", "Expect": "100-continue"})],
        )
        responses.add(responses.PUT, redirected_url, status=requests.codes.ok)

        with unittest.mock.patch.dict(os.environ, {"LSST_HTTP_PUT_SEND_EXPECT_HEADER": "True"}, clear=True):
            importlib.reload(lsst.resources.http)
            self.assertIsNone(path_expect.write(data=data))


class HttpReadWriteWebdavServerTestCase(GenericReadWriteTestCase, unittest.TestCase):
    """Test with a real webDAV server, as opposed to mocking responses."""

    scheme = "http"

    @classmethod
    def setUpClass(cls):
        cls.webdav_tmpdir = tempfile.mkdtemp(prefix="webdav-server-test-")
        cls.local_files_to_remove = []
        cls.server_thread = None

        # Should we test against a running server?
        #
        # This is convenient for testing against real servers in the
        # developer environment by initializing the environment variable
        # LSST_RESOURCES_HTTP_TEST_SERVER_URL with the URL of the server, e.g.
        #    https://dav.example.org:1234/path/to/top/dir
        if (test_endpoint := os.getenv("LSST_RESOURCES_HTTP_TEST_SERVER_URL")) is not None:
            uri = ResourcePath(test_endpoint)
            cls.scheme = uri.scheme
            cls.netloc = uri.netloc
            cls.base_path = uri.path
        elif WsgiDAVApp is not None:
            # WsgiDAVApp is available, launch a local server in its own
            # thread to test against.
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

    def test_with_webdav_server(self):
        # Creation of a remote directory  must succeed
        work_dir = ResourcePath(self._make_uri(self._get_dir_name()), forceDirectory=True)
        self.assertIsNone(work_dir.mkdir())
        self.assertTrue(work_dir.exists())
        self.assertTrue(work_dir.is_webdav_endpoint)

        # Creating an existing remote directory must succeed
        self.assertIsNone(work_dir.mkdir())

        # Test upload a randomly-generated file via write() with and without
        # overwrite
        local_file, file_size = self._generate_file()
        with open(local_file, "rb") as f:
            data = f.read()

        remote_file = work_dir.join(self._get_file_name())
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

        # Uploading a file to a non existing directory must ensure its
        # parent directories are created first and upload succeeds
        non_existing_dir = work_dir.join(self._get_dir_name(), forceDirectory=True)
        non_existing_dir = non_existing_dir.join(self._get_dir_name(), forceDirectory=True)
        non_existing_dir = non_existing_dir.join(self._get_dir_name(), forceDirectory=True)
        remote_file = non_existing_dir.join(self._get_file_name())
        self.assertIsNone(remote_file.write(data, overwrite=True))
        self.assertTrue(remote_file.exists())
        self.assertEqual(remote_file.size(), file_size)
        self.assertTrue(remote_file.parent().exists())
        downloaded_data = remote_file.read()
        download_digest = self._compute_digest(downloaded_data)
        self.assertEqual(upload_digest, download_digest)

        # Transfer from local file via "copy", with and without overwrite
        remote_file = work_dir.join(self._get_file_name())
        source_file = ResourcePath(local_file)
        self.assertIsNone(remote_file.transfer_from(source_file, transfer="copy", overwrite=True))
        self.assertTrue(remote_file.exists())
        self.assertEqual(remote_file.size(), source_file.size())
        with self.assertRaises(FileExistsError):
            remote_file.transfer_from(ResourcePath(local_file), transfer="copy", overwrite=False)

        # Transfer from remote file via "copy", with and without overwrite
        source_file = remote_file
        target_file = work_dir.join(self._get_file_name())
        self.assertIsNone(target_file.transfer_from(source_file, transfer="copy", overwrite=True))
        self.assertTrue(target_file.exists())
        self.assertEqual(target_file.size(), source_file.size())

        # Transfer without overwrite must raise since target resource exists
        with self.assertRaises(FileExistsError):
            target_file.transfer_from(source_file, transfer="copy", overwrite=False)

        # Test transfer from local file via "move", with and without overwrite
        source_file = ResourcePath(local_file)
        source_size = source_file.size()
        target_file = work_dir.join(self._get_file_name())
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
        target_file = work_dir.join(self._get_file_name())
        self.assertIsNone(target_file.transfer_from(source_file, transfer="move", overwrite=True))
        self.assertTrue(target_file.exists())
        self.assertEqual(target_file.size(), source_size)
        self.assertFalse(source_file.exists())

        # Transfer without overwrite must raise since target resource exists
        with self.assertRaises(FileExistsError):
            source_file = ResourcePath(local_file)
            target_file.transfer_from(source_file, transfer="move", overwrite=False)

        # Resource handle must succeed
        target_file = work_dir.join(self._get_file_name())
        data = "abcdefghi"
        self.assertIsNone(target_file.write(data, overwrite=True))
        with target_file.open("rb") as handle:
            handle.seek(1)
            self.assertEqual(handle.read(4).decode("utf-8"), data[1:5])

        # Deletion of an existing remote file must succeed
        self.assertIsNone(target_file.remove())

        # Deletion of a non-existing remote file must raise
        non_existing_file = work_dir.join(self._get_file_name())
        with self.assertRaises(FileNotFoundError):
            self.assertIsNone(non_existing_file.remove())

        # Deletion of an empty remote directory must succeed
        empty_dir = work_dir.join(self._get_dir_name(), forceDirectory=True)
        self.assertIsNone(empty_dir.mkdir())
        self.assertIsNone(empty_dir.remove())
        self.assertFalse(empty_dir.exists())

        # Deletion of a non-empty remote directory must succeed
        local_file, _ = self._generate_file()
        source_file = ResourcePath(local_file)
        target_file = work_dir.join(self._get_file_name())
        self.assertIsNone(target_file.transfer_from(source_file, transfer="copy", overwrite=True))
        self.assertIsNone(work_dir.remove())
        self.assertFalse(work_dir.exists())

        # Close the underlying sessions to avoid warning about sockets left
        # open by persisted connections.
        work_dir._close_sessions()

    @unittest.skip("skipped test_walk() since HttpResourcePath.walk() is not implemented")
    def test_walk(self):
        # TODO: remove this test when walk() is implemented so the super
        # class test_walk is executed.
        pass

    @unittest.skip("skipped test_large_walk() since HttpResourcePath.walk() is not implemented")
    def test_large_walk(self):
        # TODO: remove this test when walk() is implemented so the super
        # class test_large_walk is executed.
        pass

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

    def _get_name(self, prefix: str) -> str:
        alphabet = string.ascii_lowercase + string.digits
        return f"{prefix}-" + "".join(random.choices(alphabet, k=8))

    def _get_dir_name(self) -> str:
        """Return a randomly selected name for a file"""
        return self._get_name(prefix="dir")

    def _get_file_name(self) -> str:
        """Return a randomly selected name for a file"""
        return self._get_name(prefix="file")

    def _generate_file(self, remove_when_done=True) -> Tuple[str, int]:
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

    def _compute_digest(self, data: bytes) -> str:
        """Compute a SHA256 hash of data."""
        m = hashlib.sha256()
        m.update(data)
        return m.hexdigest()

    def _is_server_running(self, port: int) -> bool:
        """Return True if there is a server listening on local address
        127.0.0.1:<port>.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.connect(("127.0.0.1", port))
                return True
            except ConnectionRefusedError:
                return False


class WebdavUtilsTestCase(unittest.TestCase):
    """Test for the Webdav related utilities."""

    def setUp(self):
        self.tmpdir = ResourcePath(makeTestTempDir(TESTDIR))

    def tearDown(self):
        if self.tmpdir:
            if self.tmpdir.isLocal:
                removeTestTempDir(self.tmpdir.ospath)

    @responses.activate
    def test_is_webdav_endpoint(self):
        davEndpoint = "http://www.lsstwithwebdav.org"
        responses.add(responses.OPTIONS, davEndpoint, status=200, headers={"DAV": "1,2,3"})
        self.assertTrue(_is_webdav_endpoint(davEndpoint))

        plainHttpEndpoint = "http://www.lsstwithoutwebdav.org"
        responses.add(responses.OPTIONS, plainHttpEndpoint, status=200)
        self.assertFalse(_is_webdav_endpoint(plainHttpEndpoint))

    def test_send_expect_header(self):
        # Ensure _SEND_EXPECT_HEADER_ON_PUT is correctly initialized from
        # the environment.
        os.environ.pop("LSST_HTTP_PUT_SEND_EXPECT_HEADER", None)
        importlib.reload(lsst.resources.http)
        self.assertFalse(lsst.resources.http._SEND_EXPECT_HEADER_ON_PUT)

        with unittest.mock.patch.dict(os.environ, {"LSST_HTTP_PUT_SEND_EXPECT_HEADER": "true"}, clear=True):
            importlib.reload(lsst.resources.http)
            self.assertTrue(lsst.resources.http._SEND_EXPECT_HEADER_ON_PUT)

    def test_timeout(self):
        connect_timeout = 100
        read_timeout = 200
        with unittest.mock.patch.dict(
            os.environ,
            {"LSST_HTTP_TIMEOUT_CONNECT": str(connect_timeout), "LSST_HTTP_TIMEOUT_READ": str(read_timeout)},
            clear=True,
        ):
            # Force module reload to initialize TIMEOUT.
            importlib.reload(lsst.resources.http)
            self.assertEqual(lsst.resources.http.TIMEOUT, (connect_timeout, read_timeout))

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
