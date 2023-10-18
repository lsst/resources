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

__all__ = ("PackageResourcePath",)

import contextlib
import logging
import re
import sys

if sys.version_info < (3, 11, 0):
    # Mypy will try to use the first import it encounters and ignores
    # the sys.version_info. This means that the first import has to be
    # the backwards compatibility import since we are currently using 3.10
    # for mypy. Once we switch to 3.11 for mypy the order will have to change.
    import importlib_resources as resources
else:
    from importlib import resources  # type: ignore[no-redef]

from collections.abc import Iterator
from typing import TYPE_CHECKING

from ._resourceHandles._baseResourceHandle import ResourceHandleProtocol
from ._resourcePath import ResourcePath

if TYPE_CHECKING:
    import urllib.parse

log = logging.getLogger(__name__)


class PackageResourcePath(ResourcePath):
    """URI referring to a Python package resource.

    These URIs look like: ``resource://lsst.daf.butler/configs/file.yaml``
    where the network location is the Python package and the path is the
    resource name.
    """

    @classmethod
    def _fixDirectorySep(
        cls, parsed: urllib.parse.ParseResult, forceDirectory: bool = False
    ) -> tuple[urllib.parse.ParseResult, bool]:
        """Ensure that a path separator is present on directory paths."""
        parsed, dirLike = super()._fixDirectorySep(parsed, forceDirectory=forceDirectory)
        if not dirLike:
            try:
                # If the resource location does not exist this can
                # fail immediately. It is possible we are doing path
                # manipulation and not wanting to read the resource now,
                # so catch the error and move on.
                ref = resources.files(parsed.netloc).joinpath(parsed.path.lstrip("/"))
            except ModuleNotFoundError:
                pass
            else:
                dirLike = ref.is_dir()
        return parsed, dirLike

    def _get_ref(self) -> resources.abc.Traversable | None:
        """Obtain the object representing the resource.

        Returns
        -------
        path : `resources.abc.Traversable` or `None`
            The reference to the resource path, or `None` if the module
            associated with the resources is not accessible. This can happen
            if Python can't import the Python package defining the resource.
        """
        try:
            ref = resources.files(self.netloc).joinpath(self.relativeToPathRoot)
        except ModuleNotFoundError:
            return None
        return ref

    def isdir(self) -> bool:
        """Return True if this URI is a directory, else False."""
        if self.dirLike:  # Always bypass if we guessed the resource is a directory.
            return True
        ref = self._get_ref()
        if ref is None:
            return False  # Does not seem to exist so assume not a directory.
        return ref.is_dir()

    def exists(self) -> bool:
        """Check that the python resource exists."""
        ref = self._get_ref()
        if ref is None:
            return False
        return ref.is_file() or ref.is_dir()

    def read(self, size: int = -1) -> bytes:
        """Read the contents of the resource."""
        ref = self._get_ref()
        if not ref:
            raise FileNotFoundError(f"Unable to locate resource {self}.")
        with ref.open("rb") as fh:
            return fh.read(size)

    @contextlib.contextmanager
    def as_local(self) -> Iterator[ResourcePath]:
        """Return the location of the Python resource as local file.

        Yields
        ------
        local : `ResourcePath`
            This might be the original resource or a copy on the local file
            system.

        Notes
        -----
        The context manager will automatically delete any local temporary
        file.

        Examples
        --------
        Should be used as a context manager:

        .. code-block:: py

           with uri.as_local() as local:
               ospath = local.ospath
        """
        ref = self._get_ref()
        if ref is None:
            raise FileNotFoundError(f"Resource {self} could not be located.")
        if ref.is_dir():
            raise IsADirectoryError(f"Directory-like URI {self} cannot be fetched as local.")

        with resources.as_file(ref) as file:
            yield ResourcePath(file)

    @contextlib.contextmanager
    def open(
        self,
        mode: str = "r",
        *,
        encoding: str | None = None,
        prefer_file_temporary: bool = False,
    ) -> Iterator[ResourceHandleProtocol]:
        # Docstring inherited.
        if "r" not in mode or "+" in mode:
            raise RuntimeError(f"Package resource URI {self} is read-only.")
        ref = self._get_ref()
        if ref is None:
            raise FileNotFoundError(f"Could not open resource {self}.")
        with ref.open(mode, encoding=encoding) as buffer:
            yield buffer

    def walk(
        self, file_filter: str | re.Pattern | None = None
    ) -> Iterator[list | tuple[ResourcePath, list[str], list[str]]]:
        # Docstring inherited.
        if not self.isdir():
            raise ValueError(f"Can not walk a non-directory URI: {self}")

        if isinstance(file_filter, str):
            file_filter = re.compile(file_filter)

        ref = self._get_ref()
        if ref is None:
            raise ValueError(f"Unable to find resource {self}.")

        files: list[str] = []
        dirs: list[str] = []
        for item in ref.iterdir():
            if item.is_dir():
                dirs.append(item.name)
            elif item.is_file():
                files.append(item.name)
            # If the item wasn't covered by one of the cases above that
            # means it was deleted concurrently with this walk or is
            # not a plain file/directory/symlink

        if file_filter is not None:
            files = [f for f in files if file_filter.search(f)]

        if not dirs and not files:
            return
        else:
            yield type(self)(self, forceAbsolute=False, forceDirectory=True), dirs, files

        for dir in dirs:
            new_uri = self.join(dir, forceDirectory=True)
            yield from new_uri.walk(file_filter)
