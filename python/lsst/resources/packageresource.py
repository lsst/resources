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

import contextlib
import logging
from typing import Iterator, Optional

import pkg_resources

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

    def exists(self) -> bool:
        """Check that the python resource exists."""
        return pkg_resources.resource_exists(self.netloc, self.relativeToPathRoot)

    def read(self, size: int = -1) -> bytes:
        """Read the contents of the resource."""
        with pkg_resources.resource_stream(self.netloc, self.relativeToPathRoot) as fh:
            return fh.read(size)

    @contextlib.contextmanager
    def open(
        self,
        mode: str = "r",
        *,
        encoding: Optional[str] = None,
        prefer_file_temporary: bool = False,
    ) -> Iterator[ResourceHandleProtocol]:
        # Docstring inherited.
        if "r" not in mode or "+" in mode:
            raise RuntimeError(f"Package resource URI {self} is read-only.")
        if "b" in mode:
            with pkg_resources.resource_stream(self.netloc, self.relativeToPathRoot) as buffer:
                yield buffer
        else:
            with super().open(mode, encoding=encoding, prefer_file_temporary=prefer_file_temporary) as buffer:
                yield buffer
