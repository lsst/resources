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

__all__ = ("NoTransaction", "TransactionProtocol", "os2posix", "posix2os")

import contextlib
import logging
import os
import posixpath
import shutil
import stat
import tempfile
from collections.abc import Callable, Iterator
from pathlib import Path, PurePath, PurePosixPath
from typing import Any, Protocol

# Determine if the path separator for the OS looks like POSIX
IS_POSIX = os.sep == posixpath.sep

# Root path for this operating system. This can use getcwd which
# can fail in some situations so in the default case assume that
# posix means posix and only determine explicitly in the non-posix case.
OS_ROOT_PATH = posixpath.sep if IS_POSIX else Path().resolve().root

log = logging.getLogger(__name__)


def os2posix(ospath: str) -> str:
    """Convert a local path description to a POSIX path description.

    Parameters
    ----------
    ospath : `str`
        Path using the local path separator.

    Returns
    -------
    posix : `str`
        Path using POSIX path separator.
    """
    if IS_POSIX:
        return ospath

    posix = PurePath(ospath).as_posix()

    # PurePath strips trailing "/" from paths such that you can no
    # longer tell if a path is meant to be referring to a directory
    # Try to fix this.
    if ospath.endswith(os.sep) and not posix.endswith(posixpath.sep):
        posix += posixpath.sep

    return posix


def posix2os(posix: PurePath | str) -> str:
    """Convert a POSIX path description to a local path description.

    Parameters
    ----------
    posix : `str`, `~pathlib.PurePath`
        Path using the POSIX path separator.

    Returns
    -------
    ospath : `str`
        Path using OS path separator.
    """
    if IS_POSIX:
        return str(posix)

    posixPath = PurePosixPath(posix)
    paths = list(posixPath.parts)

    # Have to convert the root directory after splitting
    if paths[0] == posixPath.root:
        paths[0] = OS_ROOT_PATH

    # Trailing "/" is stripped so we need to add back an empty path
    # for consistency
    if str(posix).endswith(posixpath.sep):
        paths.append("")

    return os.path.join(*paths)


class NoTransaction:
    """A simple emulation of the
    `~lsst.daf.butler.core.datastore.DatastoreTransaction` class.

    Notes
    -----
    Does nothing. Used as a fallback in the absence of an explicit transaction
    class.
    """

    def __init__(self) -> None:
        return

    @contextlib.contextmanager
    def undoWith(self, name: str, undoFunc: Callable, *args: Any, **kwargs: Any) -> Iterator[None]:
        """No-op context manager to replace
        `~lsst.daf.butler.core.datastore.DatastoreTransaction`.

        Parameters
        ----------
        name : `str`
            The name of this undo request.
        undoFunc : `~collections.abc.Callable`
            Function to call if there is an exception. Not used.
        *args : `~typing.Any`
            Parameters to pass to ``undoFunc``.
        **kwargs : `~typing.Any`
            Keyword parameters to pass to ``undoFunc``.

        Yields
        ------
        `None`
            Context manager returns nothing since transactions are disabled
            by definition.
        """
        yield None


class TransactionProtocol(Protocol):
    """Protocol for type checking transaction interface."""

    @contextlib.contextmanager
    def undoWith(self, name: str, undoFunc: Callable, *args: Any, **kwargs: Any) -> Iterator[None]: ...


def makeTestTempDir(default_base: str | None = None) -> str:
    """Create a temporary directory for test usage.

    The directory will be created within ``LSST_RESOURCES_TEST_TMP`` if that
    environment variable is set, falling back to ``LSST_RESOURCES_TMPDIR``
    amd then ``default_base`` if none are set.

    Parameters
    ----------
    default_base : `str`, optional
        Default parent directory. Will use system default if no environment
        variables are set and base is set to `None`.

    Returns
    -------
    dir : `str`
        Name of the new temporary directory.
    """
    base = default_base
    for envvar in ("LSST_RESOURCES_TEST_TMP", "LSST_RESOURCES_TMPDIR"):
        if envvar in os.environ and os.environ[envvar]:
            base = os.environ[envvar]
            break
    return tempfile.mkdtemp(dir=base)


def removeTestTempDir(root: str | None) -> None:
    """Attempt to remove a temporary test directory, but do not raise if
    unable to.

    Unlike `tempfile.TemporaryDirectory`, this passes ``ignore_errors=True``
    to ``shutil.rmtree`` at close, making it safe to use on NFS.

    Parameters
    ----------
    root : `str`, optional
        Name of the directory to be removed.  If `None`, nothing will be done.
    """
    if root is not None and os.path.exists(root):
        shutil.rmtree(root, ignore_errors=True)


def ensure_directory_is_writeable(directory_path: str | bytes) -> None:
    """Given the path to a directory, ensures that we are able to write it and
    access files in it.

    Alters the directory permissions by adding the owner-write and
    owner-traverse permission bits if they aren't already set

    Parameters
    ----------
    directory_path : `str` or `bytes`
        Path to the directory that will be made writeable.
    """
    current_mode = os.stat(directory_path).st_mode
    desired_mode = current_mode | stat.S_IWUSR | stat.S_IXUSR
    if current_mode != desired_mode:
        os.chmod(directory_path, desired_mode)
