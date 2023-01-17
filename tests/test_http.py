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
from lsst.resources.http import BearerTokenAuth, SessionStore, _is_protected, _is_webdav_endpoint
from lsst.resources.tests import GenericTestCase
from lsst.resources.utils import makeTestTempDir, removeTestTempDir
from lsst.resources._resourceHandles._httpResourceHandle import HttpReadResourceHandle

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

        serverRoot = "www.not-exists.orgx"
        existingFolderName = "existingFolder"
        existingFileName = "existingFile"
        notExistingFileName = "notExistingFile"

        fileForHandleWithRange = "handleWithRange"
        fileForHandleWithOutRange = "handleWithOutRange"

        self.baseURL = ResourcePath(f"https://{serverRoot}", forceDirectory=True)
        self.existingFileResourcePath = ResourcePath(
            f"https://{serverRoot}/{existingFolderName}/{existingFileName}"
        )
        self.notExistingFileResourcePath = ResourcePath(
            f"https://{serverRoot}/{existingFolderName}/{notExistingFileName}"
        )
        self.existingFolderResourcePath = ResourcePath(
            f"https://{serverRoot}/{existingFolderName}", forceDirectory=True
        )
        self.notExistingFolderResourcePath = ResourcePath(
            f"https://{serverRoot}/{notExistingFileName}", forceDirectory=True
        )
        self.handleWithRangeResourcePath = ResourcePath(
            f"https://{serverRoot}/{existingFolderName}/{fileForHandleWithRange}"
        )
        self.handleWithOutRangeResourcePath = ResourcePath(
            f"https://{serverRoot}/{existingFolderName}/{fileForHandleWithOutRange}"
        )

        # Used by the handle tests
        responses.add(
            responses.HEAD,
            self.handleWithRangeResourcePath.geturl(),
            status=200,
            headers={"Content-Length": "1024", "Accept-Ranges": "true"},
        )
        self.handleWithRangeBody = "These are some \n bytes to read"
        responses.add(
            responses.GET,
            self.handleWithRangeResourcePath.geturl(),
            status=206,
            body=self.handleWithRangeBody.encode(),
        )
        responses.add(
            responses.PUT,
            self.handleWithRangeResourcePath.geturl(),
            status=201,
        )

        responses.add(
            responses.HEAD,
            self.handleWithOutRangeResourcePath.geturl(),
            status=200,
            headers={"Content-Length": "1024"},
        )
        responses.add(
            responses.GET,
            self.handleWithOutRangeResourcePath.geturl(),
            status=200,
            body="These are some bytes to read".encode(),
        )

        # Need to declare the options
        responses.add(responses.OPTIONS, self.baseURL.geturl(), status=200, headers={"DAV": "1,2,3"})

        # Used by HttpResourcePath.exists()
        responses.add(
            responses.HEAD,
            self.existingFileResourcePath.geturl(),
            status=200,
            headers={"Content-Length": "1024"},
        )
        responses.add(responses.HEAD, self.notExistingFileResourcePath.geturl(), status=404)

        # Used by HttpResourcePath.read()
        responses.add(
            responses.GET, self.existingFileResourcePath.geturl(), status=200, body=str.encode("It works!")
        )
        responses.add(responses.GET, self.notExistingFileResourcePath.geturl(), status=404)

        # Used by HttpResourcePath.write()
        responses.add(responses.PUT, self.existingFileResourcePath.geturl(), status=201)

        # Used by HttpResourcePath.transfer_from()
        responses.add(
            responses.Response(
                url=self.existingFileResourcePath.geturl(),
                method="COPY",
                headers={"Destination": self.existingFileResourcePath.geturl()},
                status=201,
            )
        )
        responses.add(
            responses.Response(
                url=self.existingFileResourcePath.geturl(),
                method="COPY",
                headers={"Destination": self.notExistingFileResourcePath.geturl()},
                status=201,
            )
        )
        responses.add(
            responses.Response(
                url=self.existingFileResourcePath.geturl(),
                method="MOVE",
                headers={"Destination": self.notExistingFileResourcePath.geturl()},
                status=201,
            )
        )

        # Used by HttpResourcePath.remove()
        responses.add(responses.DELETE, self.existingFileResourcePath.geturl(), status=200)
        responses.add(responses.DELETE, self.notExistingFileResourcePath.geturl(), status=404)

        # Used by HttpResourcePath.mkdir()
        responses.add(
            responses.HEAD,
            self.existingFolderResourcePath.geturl(),
            status=200,
            headers={"Content-Length": "1024"},
        )
        responses.add(responses.HEAD, self.baseURL.geturl(), status=200, headers={"Content-Length": "1024"})
        responses.add(responses.HEAD, self.notExistingFolderResourcePath.geturl(), status=404)
        responses.add(
            responses.Response(url=self.notExistingFolderResourcePath.geturl(), method="MKCOL", status=201)
        )
        responses.add(
            responses.Response(url=self.existingFolderResourcePath.geturl(), method="MKCOL", status=403)
        )

        # Used by HttpResourcePath._do_put()
        self.redirectPathNoExpect = ResourcePath(f"https://{serverRoot}/redirect-no-expect/file")
        self.redirectPathExpect = ResourcePath(f"https://{serverRoot}/redirect-expect/file")
        redirected_url = f"https://{serverRoot}/redirect/location"
        responses.add(
            responses.PUT,
            self.redirectPathNoExpect.geturl(),
            headers={"Location": redirected_url},
            status=307,
        )
        responses.add(
            responses.PUT,
            self.redirectPathExpect.geturl(),
            headers={"Location": redirected_url},
            status=307,
            match=[responses.matchers.header_matcher({"Content-Length": "0", "Expect": "100-continue"})],
        )
        responses.add(responses.PUT, redirected_url, status=202)

    def tearDown(self):
        if self.tmpdir:
            if self.tmpdir.isLocal:
                removeTestTempDir(self.tmpdir.ospath)

    @responses.activate
    def test_file_handle(self):
        # Test that without the correct header the default method is used.
        with self.handleWithOutRangeResourcePath.open('rb') as handle:
            self.assertIsInstance(handle, io.BytesIO)

        # Test that with correct header the correct handle is returned.
        with self.handleWithRangeResourcePath.open('rb') as handle:
            self.assertIsInstance(handle, HttpReadResourceHandle)

        # Test reading byte ranges works
        with self.handleWithRangeResourcePath.open('rb') as handle:
            handle = cast(HttpReadResourceHandle, handle)
            # This is not a real test, because responses can not actually
            # handle reading sub byte ranges, so the whole thing needs to be
            # read.
            result = handle.read(len(self.handleWithRangeBody)).decode()
            self.assertEqual(result, self.handleWithRangeBody)
            # Verify there is no internal buffer.
            self.assertIsNone(handle._completeBuffer)
            # Verify the position.
            self.assertEqual(handle.tell(), len(self.handleWithRangeBody))

            # Jump back to the beginning and test if reading the whole file
            # prompts the internal buffer to be read.
            handle.seek(0)
            self.assertEqual(handle.tell(), 0)
            result = handle.read().decode()
            self.assertIsNotNone(handle._completeBuffer)
            self.assertEqual(result, self.handleWithRangeBody)

        # Verify reading as a string handle works as expected.
        with self.handleWithRangeResourcePath.open('r') as handle:
            self.assertIsInstance(handle, io.TextIOWrapper)

            handle = cast(io.TextIOWrapper, handle)
            self.assertIsInstance(handle.buffer, HttpReadResourceHandle)

            # Check if string methods work.
            result = handle.read()
            self.assertEqual(result, self.handleWithRangeBody)

        # Verify that write modes invoke the default base method
        with self.handleWithRangeResourcePath.open('w') as handle:
            self.assertIsInstance(handle, io.StringIO)

    @responses.activate
    def test_exists(self):

        self.assertTrue(self.existingFileResourcePath.exists())
        self.assertFalse(self.notExistingFileResourcePath.exists())

        self.assertEqual(self.existingFileResourcePath.size(), 1024)
        with self.assertRaises(FileNotFoundError):
            self.notExistingFileResourcePath.size()

    @responses.activate
    def test_remove(self):

        self.assertIsNone(self.existingFileResourcePath.remove())
        with self.assertRaises(FileNotFoundError):
            self.notExistingFileResourcePath.remove()

        url = "https://example.org/delete"
        responses.add(responses.DELETE, url, status=404)
        with self.assertRaises(FileNotFoundError):
            ResourcePath(url).remove()

    @responses.activate
    def test_mkdir(self):

        # The mock means that we can't check this now exists
        self.notExistingFolderResourcePath.mkdir()

        # This should do nothing
        self.existingFolderResourcePath.mkdir()

        with self.assertRaises(ValueError):
            self.notExistingFileResourcePath.mkdir()

    @responses.activate
    def test_read(self):

        self.assertEqual(self.existingFileResourcePath.read().decode(), "It works!")
        self.assertNotEqual(self.existingFileResourcePath.read().decode(), "Nope.")
        with self.assertRaises(FileNotFoundError):
            self.notExistingFileResourcePath.read()

        # Run this twice to ensure use of cache in code coverage.
        for _ in (1, 2):
            with self.existingFileResourcePath.as_local() as local_uri:
                self.assertTrue(local_uri.isLocal)
                content = local_uri.read().decode()
                self.assertEqual(content, "It works!")

        # Check that the environment variable is being read.
        lsst.resources.http._TMPDIR = None
        with unittest.mock.patch.dict(os.environ, {"LSST_RESOURCES_TMPDIR": self.tmpdir.ospath}):
            with self.existingFileResourcePath.as_local() as local_uri:
                self.assertTrue(local_uri.isLocal)
                content = local_uri.read().decode()
                self.assertEqual(content, "It works!")
                self.assertIsNotNone(local_uri.relative_to(self.tmpdir))

    @responses.activate
    def test_write(self):

        self.assertIsNone(self.existingFileResourcePath.write(data=str.encode("Some content.")))
        with self.assertRaises(FileExistsError):
            self.existingFileResourcePath.write(data=str.encode("Some content."), overwrite=False)

        url = "https://example.org/put"
        responses.add(responses.PUT, url, status=404)
        with self.assertRaises(ValueError):
            ResourcePath(url).write(data=str.encode("Some content."))

    @responses.activate
    def test_do_put_with_redirection(self):

        # Without LSST_HTTP_PUT_SEND_EXPECT_HEADER.
        os.environ.pop("LSST_HTTP_PUT_SEND_EXPECT_HEADER", None)
        importlib.reload(lsst.resources.http)
        body = str.encode("any contents")
        self.assertIsNone(self.redirectPathNoExpect._do_put(data=body))

        # With LSST_HTTP_PUT_SEND_EXPECT_HEADER.
        with unittest.mock.patch.dict(os.environ, {"LSST_HTTP_PUT_SEND_EXPECT_HEADER": "True"}, clear=True):
            importlib.reload(lsst.resources.http)
            self.assertIsNone(self.redirectPathExpect._do_put(data=body))

    @responses.activate
    def test_transfer(self):

        # Transferring to self should be no-op.
        self.existingFileResourcePath.transfer_from(src=self.existingFileResourcePath)

        self.assertIsNone(self.notExistingFileResourcePath.transfer_from(src=self.existingFileResourcePath))
        # Should test for existence.
        # self.assertTrue(self.notExistingFileResourcePath.exists())

        # Should delete and try again with move.
        # self.notExistingFileResourcePath.remove()
        self.assertIsNone(
            self.notExistingFileResourcePath.transfer_from(src=self.existingFileResourcePath, transfer="move")
        )
        # Should then check that it was moved.
        # self.assertFalse(self.existingFileResourcePath.exists())

        # Existing file resource should have been removed so this should
        # trigger FileNotFoundError.
        # with self.assertRaises(FileNotFoundError):
        #    self.notExistingFileResourcePath.transfer_from(src=self.existingFileResourcePath)
        with self.assertRaises(ValueError):
            self.notExistingFileResourcePath.transfer_from(
                src=self.existingFileResourcePath, transfer="unsupported"
            )

    def test_parent(self):

        self.assertEqual(
            self.existingFolderResourcePath.geturl(), self.notExistingFileResourcePath.parent().geturl()
        )
        self.assertEqual(self.baseURL.geturl(), self.baseURL.parent().geturl())
        self.assertEqual(
            self.existingFileResourcePath.parent().geturl(), self.existingFileResourcePath.dirname().geturl()
        )

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


class WebdavUtilsTestCase(unittest.TestCase):
    """Test for the Webdav related utilities."""

    serverRoot = "www.lsstwithwebdav.orgx"
    wrongRoot = "www.lsstwithoutwebdav.org"

    def setUp(self):
        responses.add(responses.OPTIONS, f"https://{self.serverRoot}", status=200, headers={"DAV": "1,2,3"})
        responses.add(responses.OPTIONS, f"https://{self.wrongRoot}", status=200)

    @responses.activate
    def test_is_webdav_endpoint(self):

        self.assertTrue(_is_webdav_endpoint(f"https://{self.serverRoot}"))
        self.assertFalse(_is_webdav_endpoint(f"https://{self.wrongRoot}"))


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
