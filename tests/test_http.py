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

import importlib
import io
import os.path
import stat
import tempfile
import unittest
from typing import cast

import lsst.resources
import requests
import responses
from lsst.resources import ResourcePath
from lsst.resources._resourceHandles._httpResourceHandle import HttpReadResourceHandle
from lsst.resources.http import BearerTokenAuth, SessionStore, _is_protected, _is_webdav_endpoint
from lsst.resources.tests import GenericTestCase
from lsst.resources.utils import makeTestTempDir, removeTestTempDir

TESTDIR = os.path.abspath(os.path.dirname(__file__))


class GenericHttpTestCase(GenericTestCase, unittest.TestCase):
    scheme = "http"
    netloc = "server.example"


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
        with self.assertRaises(ValueError):
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

        # TODO: when testing against a real server, we should test for
        # existence of the destination file after successful "copy" or "move",
        # and for inexistance of source file after successful "move"

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
