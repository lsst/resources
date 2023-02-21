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
from __future__ import annotations

__all__ = ["GenericTestCase", "GenericReadWriteTestCase"]

import logging
import os
import pathlib
import random
import string
import unittest
import urllib.parse
import uuid
from typing import Any, Callable, Iterable, Optional, Union

from lsst.resources import ResourcePath
from lsst.resources.utils import makeTestTempDir, removeTestTempDir

TESTDIR = os.path.abspath(os.path.dirname(__file__))


def _check_open(
    test_case: Union[_GenericTestCase, unittest.TestCase],
    uri: ResourcePath,
    *,
    mode_suffixes: Iterable[str] = ("", "t", "b"),
    **kwargs: Any,
) -> None:
    """Test an implementation of ButlerURI.open.

    Parameters
    ----------
    test_case : `unittest.TestCase`
        Test case to use for assertions.
    uri : `ResourcePath`
        URI to use for tests.  Must point to a writeable location that is not
        yet occupied by a file.  On return, the location may point to a file
        only if the test fails.
    mode_suffixes : `Iterable` of `str`
        Suffixes to pass as part of the ``mode`` argument to
        `ResourcePath.open`, indicating whether to open as binary or as text;
        the only permitted elements are ``""``, ``"t"``, and ``"b"`.
    **kwargs
        Additional keyword arguments to forward to all calls to `open`.
    """
    text_content = "wxyz🙂"
    bytes_content = uuid.uuid4().bytes
    content_by_mode_suffix = {
        "": text_content,
        "t": text_content,
        "b": bytes_content,
    }
    empty_content_by_mode_suffix = {
        "": "",
        "t": "",
        "b": b"",
    }
    # To appease mypy
    double_content_by_mode_suffix = {
        "": text_content + text_content,
        "t": text_content + text_content,
        "b": bytes_content + bytes_content,
    }
    for mode_suffix in mode_suffixes:
        content = content_by_mode_suffix[mode_suffix]
        double_content = double_content_by_mode_suffix[mode_suffix]
        # Create file with mode='x', which prohibits overwriting.
        with uri.open("x" + mode_suffix, **kwargs) as write_buffer:
            write_buffer.write(content)
        test_case.assertTrue(uri.exists())
        # Check that opening with 'x' now raises, and does not modify content.
        with test_case.assertRaises(FileExistsError):
            with uri.open("x" + mode_suffix, **kwargs) as write_buffer:
                write_buffer.write("bad")
        # Read the file we created and check the contents.
        with uri.open("r" + mode_suffix, **kwargs) as read_buffer:
            test_case.assertEqual(read_buffer.read(), content)
        # Write two copies of the content, overwriting the single copy there.
        with uri.open("w" + mode_suffix, **kwargs) as write_buffer:
            write_buffer.write(double_content)
        # Read again, this time use mode='r+', which reads what is there and
        # then lets us write more; we'll use that to reset the file to one
        # copy of the content.
        with uri.open("r+" + mode_suffix, **kwargs) as rw_buffer:
            test_case.assertEqual(rw_buffer.read(), double_content)
            rw_buffer.seek(0)
            rw_buffer.truncate()
            rw_buffer.write(content)
            rw_buffer.seek(0)
            test_case.assertEqual(rw_buffer.read(), content)
        with uri.open("r" + mode_suffix, **kwargs) as read_buffer:
            test_case.assertEqual(read_buffer.read(), content)
        # Append some more content to the file; should now have two copies.
        with uri.open("a" + mode_suffix, **kwargs) as append_buffer:
            append_buffer.write(content)
        with uri.open("r" + mode_suffix, **kwargs) as read_buffer:
            test_case.assertEqual(read_buffer.read(), double_content)
        # Final mode to check is w+, which does read/write but truncates first.
        with uri.open("w+" + mode_suffix, **kwargs) as rw_buffer:
            test_case.assertEqual(rw_buffer.read(), empty_content_by_mode_suffix[mode_suffix])
            rw_buffer.write(content)
            rw_buffer.seek(0)
            test_case.assertEqual(rw_buffer.read(), content)
        with uri.open("r" + mode_suffix, **kwargs) as read_buffer:
            test_case.assertEqual(read_buffer.read(), content)
        # Remove file to make room for the next loop of tests with this URI.
        uri.remove()


class _GenericTestCase:
    """Generic base class for test mixin."""

    scheme: Optional[str] = None
    netloc: Optional[str] = None
    base_path: Optional[str] = None
    path1 = "test_dir"
    path2 = "file.txt"

    # Because we use a mixin for tests mypy needs to understand that
    # the unittest.TestCase methods exist.
    # We do not inherit from unittest.TestCase because that results
    # in the tests defined here being run as well as the tests in the
    # test file itself. We can make those tests skip but it gives an
    # uniformative view of how many tests are running.
    assertEqual: Callable
    assertNotEqual: Callable
    assertIsNone: Callable
    assertIn: Callable
    assertNotIn: Callable
    assertFalse: Callable
    assertTrue: Callable
    assertRaises: Callable
    assertLogs: Callable

    def _make_uri(self, path: str, netloc: Optional[str] = None) -> str:
        if self.scheme is not None:
            if netloc is None:
                netloc = self.netloc
            if path.startswith("/"):
                path = path[1:]
            if self.base_path is not None:
                path = f"{self.base_path}/{path}".lstrip("/")

            return f"{self.scheme}://{netloc}/{path}"
        else:
            return path


class GenericTestCase(_GenericTestCase):
    """Test cases for generic manipulation of a `ResourcePath`"""

    def setUp(self) -> None:
        if self.scheme is None:
            raise unittest.SkipTest("No scheme defined")
        self.root = self._make_uri("")
        self.root_uri = ResourcePath(self.root, forceDirectory=True, forceAbsolute=False)

    def test_creation(self) -> None:
        self.assertEqual(self.root_uri.scheme, self.scheme)
        self.assertEqual(self.root_uri.netloc, self.netloc)
        self.assertFalse(self.root_uri.query)
        self.assertFalse(self.root_uri.params)

        with self.assertRaises(ValueError):
            ResourcePath({})  # type: ignore

        with self.assertRaises(RuntimeError):
            ResourcePath(self.root_uri, isTemporary=True)

        file = self.root_uri.join("file.txt")
        with self.assertRaises(RuntimeError):
            ResourcePath(file, forceDirectory=True)

        with self.assertRaises(NotImplementedError):
            ResourcePath("unknown://netloc")

        replaced = file.replace(fragment="frag")
        self.assertEqual(replaced.fragment, "frag")

        with self.assertRaises(ValueError):
            file.replace(scheme="new")

        self.assertNotEqual(replaced, str(replaced))
        self.assertNotEqual(str(replaced), replaced)

    def test_extension(self) -> None:
        uri = ResourcePath(self._make_uri("dir/test.txt"))
        self.assertEqual(uri.updatedExtension(None), uri)
        self.assertEqual(uri.updatedExtension(".txt"), uri)
        self.assertEqual(id(uri.updatedExtension(".txt")), id(uri))

        fits = uri.updatedExtension(".fits.gz")
        self.assertEqual(fits.basename(), "test.fits.gz")
        self.assertEqual(fits.updatedExtension(".jpeg").basename(), "test.jpeg")

        extensionless = self.root_uri.join("no_ext")
        self.assertEqual(extensionless.getExtension(), "")
        extension = extensionless.updatedExtension(".fits")
        self.assertEqual(extension.getExtension(), ".fits")

    def test_relative(self) -> None:
        """Check that we can get subpaths back from two URIs"""
        parent = ResourcePath(self._make_uri(self.path1), forceDirectory=True)
        self.assertTrue(parent.isdir())
        child = parent.join("dir1/file.txt")

        self.assertEqual(child.relative_to(parent), "dir1/file.txt")

        not_child = ResourcePath("/a/b/dir1/file.txt")
        self.assertIsNone(not_child.relative_to(parent))
        self.assertFalse(not_child.isdir())

        not_directory = parent.join("dir1/file2.txt")
        self.assertIsNone(child.relative_to(not_directory))

        # Relative URIs
        parent = ResourcePath("a/b/", forceAbsolute=False)
        child = ResourcePath("a/b/c/d.txt", forceAbsolute=False)
        self.assertFalse(child.scheme)
        self.assertEqual(child.relative_to(parent), "c/d.txt")

        # forceAbsolute=True should work even on an existing ResourcePath
        self.assertTrue(pathlib.Path(ResourcePath(child, forceAbsolute=True).ospath).is_absolute())

        # Absolute URI and schemeless URI
        parent = self.root_uri.join("/a/b/c/")
        child = ResourcePath("e/f/g.txt", forceAbsolute=False)

        # If the child is relative and the parent is absolute we assume
        # that the child is a child of the parent unless it uses ".."
        self.assertEqual(child.relative_to(parent), "e/f/g.txt", f"{child}.relative_to({parent})")

        child = ResourcePath("../e/f/g.txt", forceAbsolute=False)
        self.assertIsNone(child.relative_to(parent))

        child = ResourcePath("../c/e/f/g.txt", forceAbsolute=False)
        self.assertEqual(child.relative_to(parent), "e/f/g.txt")

        # Test with different netloc
        child = ResourcePath(self._make_uri("a/b/c.txt", netloc="my.host"))
        parent = ResourcePath(self._make_uri("a", netloc="other"))
        self.assertIsNone(child.relative_to(parent), f"{child}.relative_to({parent})")

        # Schemeless absolute child.
        # Schemeless absolute URI is constructed using root= parameter.
        # For now the root parameter can not be anything other than a file.
        if self.scheme == "file":
            parent = ResourcePath("/a/b/c", root=self.root_uri)
            child = ResourcePath("d/e.txt", root=parent)
            self.assertEqual(child.relative_to(parent), "d/e.txt", f"{child}.relative_to({parent})")

            parent = ResourcePath("c/", root="/a/b/")
            self.assertEqual(child.relative_to(parent), "d/e.txt", f"{child}.relative_to({parent})")

            # Absolute schemeless child with relative parent will always fail.
            parent = ResourcePath("d/e.txt", forceAbsolute=False)
            self.assertIsNone(child.relative_to(parent), f"{child}.relative_to({parent})")

    def test_parents(self) -> None:
        """Test of splitting and parent walking."""
        parent = ResourcePath(self._make_uri("somedir"), forceDirectory=True)
        child_file = parent.join("subdir/file.txt")
        self.assertFalse(child_file.isdir())
        child_subdir, file = child_file.split()
        self.assertEqual(file, "file.txt")
        self.assertTrue(child_subdir.isdir())
        self.assertEqual(child_file.dirname(), child_subdir)
        self.assertEqual(child_file.basename(), file)
        self.assertEqual(child_file.parent(), child_subdir)
        derived_parent = child_subdir.parent()
        self.assertEqual(derived_parent, parent)
        self.assertTrue(derived_parent.isdir())
        self.assertEqual(child_file.parent().parent(), parent)

    def test_escapes(self) -> None:
        """Special characters in file paths"""
        src = self.root_uri.join("bbb/???/test.txt")
        self.assertNotIn("???", src.path)
        self.assertIn("???", src.unquoted_path)

        file = src.updatedFile("tests??.txt")
        self.assertNotIn("??.txt", file.path)

        src = src.updatedFile("tests??.txt")
        self.assertIn("??.txt", src.unquoted_path)

        # File URI and schemeless URI
        parent = ResourcePath(self._make_uri(urllib.parse.quote("/a/b/c/de/??/")))
        child = ResourcePath("e/f/g.txt", forceAbsolute=False)
        self.assertEqual(child.relative_to(parent), "e/f/g.txt")

        child = ResourcePath("e/f??#/g.txt", forceAbsolute=False)
        self.assertEqual(child.relative_to(parent), "e/f??#/g.txt")

        child = ResourcePath(self._make_uri(urllib.parse.quote("/a/b/c/de/??/e/f??#/g.txt")))
        self.assertEqual(child.relative_to(parent), "e/f??#/g.txt")

        self.assertEqual(child.relativeToPathRoot, "a/b/c/de/??/e/f??#/g.txt")

        # dir.join() morphs into a file scheme
        dir = ResourcePath(self._make_uri(urllib.parse.quote("bbb/???/")))
        new = dir.join("test_j.txt")
        self.assertIn("???", new.unquoted_path, f"Checking {new}")

        new2name = "###/test??.txt"
        new2 = dir.join(new2name)
        self.assertIn("???", new2.unquoted_path)
        self.assertTrue(new2.unquoted_path.endswith(new2name))

        fdir = dir.abspath()
        self.assertNotIn("???", fdir.path)
        self.assertIn("???", fdir.unquoted_path)
        self.assertEqual(fdir.scheme, self.scheme)

        fnew2 = fdir.join(new2name)
        self.assertTrue(fnew2.unquoted_path.endswith(new2name))
        self.assertNotIn("###", fnew2.path)

        # Test that children relative to schemeless and file schemes
        # still return the same unquoted name
        self.assertEqual(fnew2.relative_to(fdir), new2name, f"{fnew2}.relative_to({fdir})")
        self.assertEqual(fnew2.relative_to(dir), new2name, f"{fnew2}.relative_to({dir})")
        self.assertEqual(new2.relative_to(fdir), new2name, f"{new2}.relative_to({fdir})")
        self.assertEqual(new2.relative_to(dir), new2name, f"{new2}.relative_to({dir})")

        # Check for double quoting
        plus_path = "/a/b/c+d/"
        with self.assertLogs(level="WARNING"):
            uri = ResourcePath(urllib.parse.quote(plus_path), forceDirectory=True)
        self.assertEqual(uri.ospath, plus_path)

        # Check that # is not escaped for schemeless URIs
        hash_path = "/a/b#/c&d#xyz"
        hpos = hash_path.rfind("#")
        uri = ResourcePath(hash_path)
        self.assertEqual(uri.ospath, hash_path[:hpos])
        self.assertEqual(uri.fragment, hash_path[hpos + 1 :])

    def test_hash(self) -> None:
        """Test that we can store URIs in sets and as keys."""
        uri1 = self.root_uri
        uri2 = uri1.join("test/")
        s = {uri1, uri2}
        self.assertIn(uri1, s)

        d = {uri1: "1", uri2: "2"}
        self.assertEqual(d[uri2], "2")

    def test_root_uri(self) -> None:
        """Test ResourcePath.root_uri()."""
        uri = ResourcePath(self._make_uri("a/b/c.txt"))
        self.assertEqual(uri.root_uri().geturl(), self.root)

    def test_join(self) -> None:
        """Test .join method."""
        root_str = self.root
        root = self.root_uri

        self.assertEqual(root.join("b/test.txt").geturl(), f"{root_str}b/test.txt")
        add_dir = root.join("b/c/d/")
        self.assertTrue(add_dir.isdir())
        self.assertEqual(add_dir.geturl(), f"{root_str}b/c/d/")

        up_relative = root.join("../b/c.txt")
        self.assertFalse(up_relative.isdir())
        self.assertEqual(up_relative.geturl(), f"{root_str}b/c.txt")

        quote_example = "hsc/payload/b&c.t@x#t"
        needs_quote = root.join(quote_example)
        self.assertEqual(needs_quote.unquoted_path, "/" + quote_example)

        other = ResourcePath(f"{self.root}test.txt")
        self.assertEqual(root.join(other), other)
        self.assertEqual(other.join("b/new.txt").geturl(), f"{self.root}b/new.txt")

        joined = ResourcePath(f"{self.root}hsc/payload/").join(
            ResourcePath("test.qgraph", forceAbsolute=False)
        )
        self.assertEqual(joined, ResourcePath(f"{self.root}hsc/payload/test.qgraph"))

        with self.assertRaises(ValueError):
            ResourcePath(f"{self.root}hsc/payload/").join(ResourcePath("test.qgraph"))

    def test_quoting(self) -> None:
        """Check that quoting works."""
        parent = ResourcePath(self._make_uri("rootdir"), forceDirectory=True)
        subpath = "rootdir/dir1+/file?.txt"
        child = ResourcePath(self._make_uri(urllib.parse.quote(subpath)))

        self.assertEqual(child.relative_to(parent), "dir1+/file?.txt")
        self.assertEqual(child.basename(), "file?.txt")
        self.assertEqual(child.relativeToPathRoot, subpath)
        self.assertIn("%", child.path)
        self.assertEqual(child.unquoted_path, "/" + subpath)

    def test_ordering(self) -> None:
        """Check that greater/less comparison operators work."""
        a = self._make_uri("a.txt")
        b = self._make_uri("b/")
        self.assertTrue(a < b)
        self.assertFalse(a < a)
        self.assertTrue(a <= b)
        self.assertTrue(a <= a)
        self.assertTrue(b > a)
        self.assertFalse(b > b)
        self.assertTrue(b >= a)
        self.assertTrue(b >= b)


class GenericReadWriteTestCase(_GenericTestCase):
    """Test schemes that can read and write using concrete resources."""

    transfer_modes = ("copy", "move")
    testdir: Optional[str] = None

    def setUp(self) -> None:
        if self.scheme is None:
            raise unittest.SkipTest("No scheme defined")
        self.root = self._make_uri("")
        self.root_uri = ResourcePath(self.root, forceDirectory=True, forceAbsolute=False)

        if self.scheme == "file":
            # Use a local tempdir because on macOS the temp dirs use symlinks
            # so relsymlink gets quite confused.
            self.tmpdir = ResourcePath(makeTestTempDir(self.testdir))
        else:
            # Create random tmp directory relative to the test root.
            self.tmpdir = self.root_uri.join(
                "TESTING-" + "".join(random.choices(string.ascii_lowercase + string.digits, k=8)),
                forceDirectory=True,
            )
            self.tmpdir.mkdir()

    def tearDown(self) -> None:
        if self.tmpdir:
            if self.tmpdir.isLocal:
                removeTestTempDir(self.tmpdir.ospath)

    def test_file(self) -> None:
        uri = self.tmpdir.join("test.txt")
        self.assertFalse(uri.exists(), f"{uri} should not exist")
        self.assertTrue(uri.path.endswith("test.txt"))

        content = "abcdefghijklmnopqrstuv\n"
        uri.write(content.encode())
        self.assertTrue(uri.exists(), f"{uri} should now exist")
        self.assertEqual(uri.read().decode(), content)
        self.assertEqual(uri.size(), len(content.encode()))

        with self.assertRaises(FileExistsError):
            uri.write(b"", overwrite=False)

        # Not all backends can tell if a remove fails so we can not
        # test that a remove of a non-existent entry is guaranteed to raise.
        uri.remove()
        self.assertFalse(uri.exists())

        # Ideally the test would remove the file again and raise a
        # FileNotFoundError. This is not reliable for remote resources
        # and doing an explicit check before trying to remove the resource
        # just to raise an exception is deemed an unacceptable overhead.

        with self.assertRaises(FileNotFoundError):
            uri.read()

        with self.assertRaises(FileNotFoundError):
            self.tmpdir.join("file/not/there.txt").size()

        # Check that creating a URI from a URI returns the same thing
        uri2 = ResourcePath(uri)
        self.assertEqual(uri, uri2)
        self.assertEqual(id(uri), id(uri2))

    def test_mkdir(self) -> None:
        newdir = self.tmpdir.join("newdir/seconddir", forceDirectory=True)
        newdir.mkdir()
        self.assertTrue(newdir.exists())
        self.assertEqual(newdir.size(), 0)

        newfile = newdir.join("temp.txt")
        newfile.write("Data".encode())
        self.assertTrue(newfile.exists())

        file = self.tmpdir.join("file.txt")
        # Some schemes will realize that the URI is not a file and so
        # will raise NotADirectoryError. The file scheme is more permissive
        # and lets you write anything but will raise NotADirectoryError
        # if a non-directory is already there. We therefore write something
        # to the file to ensure that we trigger a portable exception.
        file.write(b"")
        with self.assertRaises(NotADirectoryError):
            file.mkdir()

        # The root should exist.
        self.root_uri.mkdir()
        self.assertTrue(self.root_uri.exists())

    def test_transfer(self) -> None:
        src = self.tmpdir.join("test.txt")
        content = "Content is some content\nwith something to say\n\n"
        src.write(content.encode())

        can_move = "move" in self.transfer_modes
        for mode in self.transfer_modes:
            if mode == "move":
                continue

            dest = self.tmpdir.join(f"dest_{mode}.txt")
            # Ensure that we get some debugging output.
            with self.assertLogs("lsst.resources", level=logging.DEBUG) as cm:
                dest.transfer_from(src, transfer=mode)
            self.assertIn("Transferring ", "\n".join(cm.output))
            self.assertTrue(dest.exists(), f"Check that {dest} exists (transfer={mode})")

            new_content = dest.read().decode()
            self.assertEqual(new_content, content)

            if mode in ("symlink", "relsymlink"):
                self.assertTrue(os.path.islink(dest.ospath), f"Check that {dest} is symlink")

            # If the source and destination are hardlinks of each other
            # the transfer should work even if overwrite=False.
            if mode in ("link", "hardlink"):
                dest.transfer_from(src, transfer=mode)
            else:
                with self.assertRaises(
                    FileExistsError, msg=f"Overwrite of {dest} should not be allowed ({mode})"
                ):
                    dest.transfer_from(src, transfer=mode)

            # Transfer again and overwrite.
            dest.transfer_from(src, transfer=mode, overwrite=True)

            dest.remove()

        b = src.read()
        self.assertEqual(b.decode(), new_content)

        nbytes = 10
        subset = src.read(size=nbytes)
        self.assertEqual(len(subset), nbytes)
        self.assertEqual(subset.decode(), content[:nbytes])

        # Transferring to self should be okay.
        src.transfer_from(src, "auto")

        with self.assertRaises(ValueError):
            src.transfer_from(src, transfer="unknown")

        # A move transfer is special.
        if can_move:
            dest.transfer_from(src, transfer="move")
            self.assertFalse(src.exists())
            self.assertTrue(dest.exists())
        else:
            src.remove()

        dest.remove()
        with self.assertRaises(FileNotFoundError):
            dest.transfer_from(src, "auto")

    def test_local_transfer(self) -> None:
        """Test we can transfer to and from local file."""
        remote_src = self.tmpdir.join("src.json")
        remote_src.write(b"42")
        remote_dest = self.tmpdir.join("dest.json")

        with ResourcePath.temporary_uri(suffix=".json") as tmp:
            self.assertTrue(tmp.isLocal)
            tmp.transfer_from(remote_src, transfer="auto")
            self.assertEqual(tmp.read(), remote_src.read())

            remote_dest.transfer_from(tmp, transfer="auto")
            self.assertEqual(remote_dest.read(), tmp.read())

        # Temporary (possibly remote) resource.
        # Transfers between temporary resources.
        with ResourcePath.temporary_uri(prefix=self.tmpdir.join("tmp"), suffix=".json") as remote_tmp:
            # Temporary local resource.
            with ResourcePath.temporary_uri(suffix=".json") as local_tmp:
                remote_tmp.write(b"42")
                if not remote_tmp.isLocal:
                    for transfer in ("link", "symlink", "hardlink", "relsymlink"):
                        with self.assertRaises(RuntimeError):
                            # Trying to symlink a remote resource is not going
                            # to work. A hardlink could work but would rely
                            # on the local temp space being on the same
                            # filesystem as the target.
                            local_tmp.transfer_from(remote_tmp, transfer)
                local_tmp.transfer_from(remote_tmp, "move")
                self.assertFalse(remote_tmp.exists())
                remote_tmp.transfer_from(local_tmp, "auto", overwrite=True)
                self.assertEqual(local_tmp.read(), remote_tmp.read())

                # Transfer of missing remote.
                remote_tmp.remove()
                with self.assertRaises(FileNotFoundError):
                    local_tmp.transfer_from(remote_tmp, "auto", overwrite=True)

    def test_local(self) -> None:
        """Check that remote resources can be made local."""
        src = self.tmpdir.join("test.txt")
        original_content = "Content is some content\nwith something to say\n\n"
        src.write(original_content.encode())

        # Run this twice to ensure use of cache in code coverage
        # if applicable.
        for _ in (1, 2):
            with src.as_local() as local_uri:
                self.assertTrue(local_uri.isLocal)
                content = local_uri.read().decode()
                self.assertEqual(content, original_content)

                if src.isLocal:
                    self.assertEqual(src, local_uri)

        with self.assertRaises(IsADirectoryError):
            with self.root_uri.as_local() as local_uri:
                pass

    def test_walk(self) -> None:
        """Walk a directory hierarchy."""
        root = self.tmpdir.join("walk/")

        # Look for a file that is not there
        file = root.join("config/basic/butler.yaml")
        found_list = list(ResourcePath.findFileResources([file]))
        self.assertEqual(found_list[0], file)

        # First create the files (content is irrelevant).
        expected_files = {
            "dir1/a.yaml",
            "dir1/b.yaml",
            "dir1/c.json",
            "dir2/d.json",
            "dir2/e.yaml",
        }
        expected_uris = {root.join(f) for f in expected_files}
        for uri in expected_uris:
            uri.write(b"")
            self.assertTrue(uri.exists())

        # Look for the files.
        found = set(ResourcePath.findFileResources([root]))
        self.assertEqual(found, expected_uris)

        # Now solely the YAML files.
        expected_yaml = {u for u in expected_uris if u.getExtension() == ".yaml"}
        found = set(ResourcePath.findFileResources([root], file_filter=r".*\.yaml$"))
        self.assertEqual(found, expected_yaml)

        # Now two explicit directories and a file
        expected = set(u for u in expected_yaml)
        expected.add(file)

        found = set(
            ResourcePath.findFileResources(
                [file, root.join("dir1/"), root.join("dir2/")],
                file_filter=r".*\.yaml$",
            )
        )
        self.assertEqual(found, expected)

        # Group by directory -- find everything and compare it with what
        # we expected to be there in total.
        found_yaml = set()
        counter = 0
        for uris in ResourcePath.findFileResources([file, root], file_filter=r".*\.yaml$", grouped=True):
            assert not isinstance(uris, ResourcePath)  # for mypy.
            found_uris = set(uris)
            if found_uris:
                counter += 1

            found_yaml.update(found_uris)

        expected_yaml_2 = expected_yaml
        expected_yaml_2.add(file)
        self.assertEqual(found_yaml, expected_yaml)
        self.assertEqual(counter, 3)

        # Grouping but check that single files are returned in a single group
        # at the end
        file2 = root.join("config/templates/templates-bad.yaml")
        found_grouped = [
            [uri for uri in group]
            for group in ResourcePath.findFileResources([file, file2, root.join("dir2/")], grouped=True)
            if not isinstance(group, ResourcePath)  # For mypy.
        ]
        self.assertEqual(len(found_grouped), 2, f"Found: {list(found_grouped)}")
        self.assertEqual(list(found_grouped[1]), [file, file2])

        with self.assertRaises(ValueError):
            # The list forces the generator to run.
            list(file.walk())

        # A directory that does not exist returns nothing.
        self.assertEqual(list(root.join("dir3/").walk()), [])

    def test_large_walk(self) -> None:
        # In some systems pagination is used so ensure that we can handle
        # large numbers of files. For example S3 limits us to 1000 responses
        # per listing call.
        created = set()
        counter = 1
        n_dir1 = 1100
        root = self.tmpdir.join("large_walk", forceDirectory=True)
        while counter <= n_dir1:
            new = ResourcePath(root.join(f"file{counter:04d}.txt"))
            new.write(f"{counter}".encode())
            created.add(new)
            counter += 1
        counter = 1
        # Put some in a subdirectory to make sure we are looking in a
        # hierarchy.
        n_dir2 = 100
        subdir = root.join("subdir", forceDirectory=True)
        while counter <= n_dir2:
            new = ResourcePath(subdir.join(f"file{counter:04d}.txt"))
            new.write(f"{counter}".encode())
            created.add(new)
            counter += 1

        found = set(ResourcePath.findFileResources([root]))
        self.assertEqual(len(found), n_dir1 + n_dir2)
        self.assertEqual(found, created)

        # Again with grouping.
        # (mypy gets upset not knowing which of the two options is being
        # returned so add useless instance check).
        found_list = list(
            [uri for uri in group]
            for group in ResourcePath.findFileResources([root], grouped=True)
            if not isinstance(group, ResourcePath)  # For mypy.
        )
        self.assertEqual(len(found_list), 2)
        self.assertEqual(len(found_list[0]), n_dir1)
        self.assertEqual(len(found_list[1]), n_dir2)

    def test_temporary(self) -> None:
        prefix = self.tmpdir.join("tmp", forceDirectory=True)
        with ResourcePath.temporary_uri(prefix=prefix, suffix=".json") as tmp:
            self.assertEqual(tmp.getExtension(), ".json", f"uri: {tmp}")
            self.assertTrue(tmp.isabs(), f"uri: {tmp}")
            self.assertFalse(tmp.exists(), f"uri: {tmp}")
            tmp.write(b"abcd")
            self.assertTrue(tmp.exists(), f"uri: {tmp}")
            self.assertTrue(tmp.isTemporary)
        self.assertFalse(tmp.exists(), f"uri: {tmp}")

        tmpdir = ResourcePath(self.tmpdir, forceDirectory=True)
        with ResourcePath.temporary_uri(prefix=tmpdir) as tmp:
            # Use a specified tmpdir and check it is okay for the file
            # to not be created.
            self.assertFalse(tmp.getExtension())
            self.assertFalse(tmp.exists(), f"uri: {tmp}")
            self.assertEqual(tmp.scheme, self.scheme)
            self.assertTrue(tmp.isTemporary)
        self.assertTrue(tmpdir.exists(), f"uri: {tmpdir} still exists")

        # Fake a directory suffix.
        with self.assertRaises(NotImplementedError):
            with ResourcePath.temporary_uri(prefix=self.root_uri, suffix="xxx/") as tmp:
                pass

    def test_open(self) -> None:
        tmpdir = ResourcePath(self.tmpdir, forceDirectory=True)
        with ResourcePath.temporary_uri(prefix=tmpdir, suffix=".txt") as tmp:
            _check_open(self, tmp, mode_suffixes=("", "t"))
            _check_open(self, tmp, mode_suffixes=("t",), encoding="utf-16")
            _check_open(self, tmp, mode_suffixes=("t",), prefer_file_temporary=True)
            _check_open(self, tmp, mode_suffixes=("t",), encoding="utf-16", prefer_file_temporary=True)
        with ResourcePath.temporary_uri(prefix=tmpdir, suffix=".dat") as tmp:
            _check_open(self, tmp, mode_suffixes=("b",))
            _check_open(self, tmp, mode_suffixes=("b",), prefer_file_temporary=True)

        with self.assertRaises(IsADirectoryError):
            with self.root_uri.open():
                pass

    def test_mexists(self) -> None:
        root = self.tmpdir.join("mexists/")

        # A file that is not there.
        file = root.join("config/basic/butler.yaml")

        # Create some files.
        expected_files = {
            "dir1/a.yaml",
            "dir1/b.yaml",
            "dir2/e.yaml",
        }
        expected_uris = {root.join(f) for f in expected_files}
        for uri in expected_uris:
            uri.write(b"")
            self.assertTrue(uri.exists())
        expected_uris.add(file)

        multi = ResourcePath.mexists(expected_uris)

        for uri, is_there in multi.items():
            if uri == file:
                self.assertFalse(is_there)
            else:
                self.assertTrue(is_there)
