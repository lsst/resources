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

__all__ = ("NoTransaction", "TransactionProtocol", "get_tempdir", "os2posix", "posix2os")

import contextlib
import logging
import multiprocessing
import os
import posixpath
import shutil
import stat
import tempfile
from collections.abc import Callable, Iterator
from functools import cache
from pathlib import Path, PurePath, PurePosixPath
from typing import Any, Protocol

# Determine if the path separator for the OS looks like POSIX
IS_POSIX = os.sep == posixpath.sep

# Root path for this operating system. This can use getcwd which
# can fail in some situations so in the default case assume that
# posix means posix and only determine explicitly in the non-posix case.
OS_ROOT_PATH = posixpath.sep if IS_POSIX else Path().resolve().root

# Maximum number of worker threads for parallelized operations.
# If greater than 10, be aware that this number has to be consistent
# with connection pool sizing (for example in urllib3).
MAX_WORKERS = 10

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


@cache
def get_tempdir() -> str:
    """Get POSIX path to temporary directory.

    Returns
    -------
    tmpdir : `str`
        Path to the default temporary directory location.

    Notes
    -----
    Uses the value of environment variables ``LSST_RESOURCES_TMPDIR`` or
    ``TMPDIR``, if defined. Otherwise use the system temporary directory,
    with a last-resort fallback to the current working directory if
    nothing else is available.
    """
    tmpdir = None
    # $TMPDIR is also checked with getttempdir() below.
    for dir in (os.getenv(v) for v in ("LSST_RESOURCES_TMPDIR", "TMPDIR")):
        if dir and os.path.isdir(dir):
            tmpdir = dir
            break

    if tmpdir is None:
        tmpdir = tempfile.gettempdir()

    return tmpdir


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


def _get_int_env_var(env_var: str) -> int | None:
    int_value = None
    env_value = os.getenv(env_var)
    if env_value is not None:
        with contextlib.suppress(TypeError):
            int_value = int(env_value)
    return int_value


@cache
def _get_num_workers() -> int:
    f"""Calculate the number of workers to use.

    Returns
    -------
    num : `int`
        The number of workers to use. Will use the value of the
        ``LSST_RESOURCES_NUM_WORKERS`` environment variable if set. Will fall
        back to using the CPU count (plus 2) but capped at {MAX_WORKERS}.
    """
    num_workers: int | None = None
    num_workers = _get_int_env_var("LSST_RESOURCES_NUM_WORKERS")

    # If someone is explicitly specifying a number, let them use that number.
    if num_workers is not None:
        return num_workers

    if num_workers is None:
        # CPU_LIMIT is used on nublado.
        cpu_limit = _get_int_env_var("CPU_LIMIT") or multiprocessing.cpu_count()
        if cpu_limit is not None:
            num_workers = cpu_limit + 2

    # But don't ever return more than the maximum allowed.
    return min([num_workers, MAX_WORKERS])
