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
from collections.abc import Iterator
from importlib import resources
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    try:
        import fsspec
        from fsspec.spec import AbstractFileSystem
    except ImportError:
        fsspec = None
        AbstractFileSystem = type

from ._resourceHandles._baseResourceHandle import ResourceHandleProtocol
from ._resourcePath import ResourcePath

log = logging.getLogger(__name__)


class PackageResourcePath(ResourcePath):
    """URI referring to a Python package resource.

    These URIs look like: ``resource://lsst.daf.butler/configs/file.yaml``
    where the network location is the Python package and the path is the
    resource name.
    """

    def _get_ref(self) -> resources.abc.Traversable | None:
        """Obtain the object representing the resource.

        Returns
        -------
        path : `resources.abc.Traversable` or `None`
            The reference to the resource path, or `None` if the module
            associated with the resources is not accessible. This can happen
            if Python can't import the Python package defining the resource.
        """
        # Need the path without the leading /.
        path = self.path.lstrip("/")
        try:
            ref = resources.files(self.netloc).joinpath(path)
        except ModuleNotFoundError:
            return None
        return ref

    def isdir(self) -> bool:
        """Return True if this URI is a directory, else False."""
        if self.dirLike is None:
            ref = self._get_ref()
            if ref is not None:
                self.dirLike = ref.is_dir()
            else:
                return False
        return self.dirLike

    def exists(self) -> bool:
        """Check that the python resource exists."""
        ref = self._get_ref()
        if ref is None:
            return False
        return ref.is_file() or ref.is_dir()

    def read(self, size: int = -1) -> bytes:
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
        # mypy uses the literal value of mode to work out the parameters
        # and return value but mode here is a variable.
        with ref.open(mode, encoding=encoding) as buffer:  # type: ignore[call-overload]
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

    def to_fsspec(self) -> tuple[AbstractFileSystem, str]:
        """Return an abstract file system and path that can be used by fsspec.

        Python package resources are effectively local files in most cases
        but can be found inside ZIP files. To support this we would have
        to change this API to a context manager (using
        ``importlib.resources.as_file``) or find an API where fsspec knows
        about python package resource.

        Returns
        -------
        fs : `fsspec.spec.AbstractFileSystem`
            A file system object suitable for use with the returned path.
        path : `str`
            A path that can be opened by the file system object.
        """
        raise NotImplementedError("fsspec can not be used with python package resources.")
