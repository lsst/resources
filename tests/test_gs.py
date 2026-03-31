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

"""Tests for the ``gs://`` resource backend.

The emulator-backed tests in this module are enabled in either of these ways:

1. Set ``STORAGE_EMULATOR_HOST`` to an already-running GCS emulator
   endpoint. This is how GitHub Actions runs these tests.
2. Install the ``fake-gcs-server`` binary locally and make it available on
   ``PATH``, or set ``FAKE_GCS_SERVER`` to its full path. The test helper will
   start and stop the emulator automatically.

The server binary is available from:
https://github.com/fsouza/fake-gcs-server/releases

If neither is configured, the emulator-backed tests are skipped.
"""

from __future__ import annotations

import contextlib
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
import uuid
from collections import deque
from threading import Thread
from unittest import mock

import lsst.resources.gs as gs_module
from lsst.resources import ResourceInfo, ResourcePath
from lsst.resources.gs import GSResourcePath
from lsst.resources.tests import GenericTestCase

try:
    from google.cloud import storage
except ImportError:
    storage = None


def _find_free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@contextlib.contextmanager
def _reset_gs_client() -> None:
    old_client = GSResourcePath._client
    old_global_client = gs_module._client
    GSResourcePath._client = None
    gs_module._client = None
    try:
        yield
    finally:
        GSResourcePath._client = None
        gs_module._client = old_global_client
        GSResourcePath._client = old_client


@contextlib.contextmanager
def fake_gcs_server():
    """Start or connect to a fake GCS server."""
    if storage is None:
        raise unittest.SkipTest("google-cloud-storage is not installed")

    emulator_host = os.environ.get("STORAGE_EMULATOR_HOST")
    if emulator_host:
        env = {"GOOGLE_CLOUD_PROJECT": os.environ.get("GOOGLE_CLOUD_PROJECT", "test-project")}
        with mock.patch.dict(os.environ, env, clear=False):
            with _reset_gs_client():
                yield storage.Client()
        return

    binary = os.environ.get("FAKE_GCS_SERVER") or shutil.which("fake-gcs-server")
    if binary is None:
        raise unittest.SkipTest("fake-gcs-server is not installed")

    port = _find_free_port()
    filesystem_root = tempfile.mkdtemp(prefix="fake-gcs-server-")
    startup_output: deque[str] = deque(maxlen=50)
    proc = subprocess.Popen(
        [binary, "-scheme", "http", "-port", str(port), "-filesystem-root", filesystem_root],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    def _drain_output() -> None:
        assert proc.stdout is not None
        for line in proc.stdout:
            startup_output.append(line.rstrip())

    output_thread = Thread(target=_drain_output, daemon=True)
    output_thread.start()
    try:
        deadline = time.time() + 10
        while True:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    break
            except OSError:
                if proc.poll() is not None:
                    details = "\n".join(startup_output) or "no process output captured"
                    raise RuntimeError(
                        f"fake-gcs-server exited unexpectedly with code {proc.returncode}:\n{details}"
                    ) from None
                if time.time() > deadline:
                    details = "\n".join(startup_output) or "no process output captured"
                    raise RuntimeError(f"Timed out waiting for fake-gcs-server:\n{details}") from None
                time.sleep(0.1)

        env = {
            "STORAGE_EMULATOR_HOST": f"http://127.0.0.1:{port}",
            "GOOGLE_CLOUD_PROJECT": "test-project",
        }
        with mock.patch.dict(os.environ, env, clear=False):
            with _reset_gs_client():
                yield storage.Client()
    finally:
        proc.terminate()
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=5)
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        output_thread.join(timeout=1)
        shutil.rmtree(filesystem_root, ignore_errors=True)


class GenericGSTestCase(GenericTestCase, unittest.TestCase):
    """Generic URI property testing."""

    scheme = "gs"
    netloc = "my_bucket"


class GSReadWriteTestCase(unittest.TestCase):
    """Test GCS backend with emulated server."""

    def setUp(self) -> None:
        self.server = self.enterContext(fake_gcs_server())
        test_id = re.sub(r"[^a-z0-9-]", "-", self.id().lower()).strip("-")
        suffix = uuid.uuid4().hex[:8]
        self.bucket = f"{test_id[:54]}-{suffix}"
        self.server.create_bucket(self.bucket)
        self.root_uri = ResourcePath(f"gs://{self.bucket}/", forceDirectory=True, forceAbsolute=False)
        self.tmpdir = self.root_uri.join("TESTING/", forceDirectory=True)

    def test_file_round_trip(self) -> None:
        uri = self.tmpdir.join("test.txt")
        content = b"abcdefghijklmnopqrstuv\n"

        self.assertFalse(uri.exists())
        uri.write(content)
        self.assertTrue(uri.exists())
        self.assertEqual(uri.read(), content)
        self.assertEqual(uri.size(), len(content))

    def test_get_info(self) -> None:
        remote = self.tmpdir.join("test-info.dat")
        remote.write(b"abc")

        info = remote.get_info()
        self.assertIsInstance(info, ResourceInfo)
        self.assertTrue(info.is_file)
        self.assertEqual(info.size, 3)
        self.assertIsNotNone(info.creation_time)
        self.assertIsNotNone(info.last_modified)
        self.assertIsInstance(info.checksums, dict)

    def test_directory_semantics(self) -> None:
        newdir = self.tmpdir.join("newdir/seconddir", forceDirectory=True)
        newdir.mkdir()
        self.assertTrue(newdir.exists())

        info = newdir.get_info()
        self.assertFalse(info.is_file)
        self.assertEqual(info.size, 0)
        self.assertEqual(info.checksums, {})

        newfile = newdir.join("temp.txt")
        newfile.write(b"Data")
        self.assertTrue(newfile.exists())

    def test_root_missing_bucket(self) -> None:
        missing = ResourcePath("gs://missing-bucket/", forceDirectory=True, forceAbsolute=False)
        self.assertFalse(missing.exists())
        with self.assertRaises(FileNotFoundError):
            missing.get_info()
