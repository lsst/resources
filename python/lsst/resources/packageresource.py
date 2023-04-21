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

import contextlib
import logging
import re
from importlib import resources
from typing import Iterator

__all__ = ("PackageResourcePath",)

from ._resourceHandles._baseResourceHandle import ResourceHandleProtocol
from ._resourcePath import ResourcePath

log = logging.getLogger(__name__)


class PackageResourcePath(ResourcePath):
    """URI referring to a Python package resource.

    These URIs look like: ``resource://lsst.daf.butler/configs/file.yaml``
    where the network location is the Python package and the path is the
    resource name.
    """

    def _reallocate_path(self) -> tuple[str, str]:
        """Convert netloc + path + file into resource + file.

        Returns
        -------
        package : `str`
            The package name including any path component and using dot
            separator.
        resource : `str`
            The file resource without a path component.

        Notes
        -----
        The ``importlib.resources`` package thinks that resources are files
        without any path component. This means that the path component has
        to be combined with the ``netloc`` component before it can be used.
        This behavior differs from ``pkg_resources``.
        """
        package = self.netloc
        parent_uri, resource = self.split()
        path = parent_uri.path.strip("/")
        sub_package = path.replace("/", ".")
        if sub_package:
            package += "." + sub_package
        return package, resource

    def exists(self) -> bool:
        """Check that the python resource exists."""
        package, resource = self._reallocate_path()
        return resources.is_resource(package, resource)

    def read(self, size: int = -1) -> bytes:
        """Read the contents of the resource."""
        package, resource = self._reallocate_path()
        if size < 0:
            return resources.read_binary(package, resource)
        with resources.open_binary(package, resource) as fh:
            return fh.read(size)

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
        package, resource = self._reallocate_path()
        if "b" in mode:
            with resources.open_binary(package, resource) as buffer:
                yield buffer
        else:
            kwargs = {}
            if encoding is not None:
                kwargs["encoding"] = encoding

            with resources.open_text(package, resource, **kwargs) as buffer:
                yield buffer

    def walk(
        self, file_filter: str | re.Pattern | None = None
    ) -> Iterator[list | tuple[ResourcePath, list[str], list[str]]]:
        # Docstring inherited.
        if not self.dirLike:
            raise ValueError("Can not walk a non-directory URI")

        if isinstance(file_filter, str):
            file_filter = re.compile(file_filter)

        package, _ = self._reallocate_path()

        files: list[str] = []
        dirs: list[str] = []
        for item in resources.contents(package):
            if resources.is_resource(package, item):
                # This is a file.
                files.append(item)
            else:
                # This is a directory.
                dirs.append(item)

        if file_filter is not None:
            files = [f for f in files if file_filter.search(f)]

        if not dirs and not files:
            return
        else:
            yield type(self)(self, forceAbsolute=False, forceDirectory=True), dirs, files

        for dir in dirs:
            new_uri = self.join(dir, forceDirectory=True)
            yield from new_uri.walk(file_filter)
