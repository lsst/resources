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

__all__ = ("RemoteTestResourcePath",)

import contextlib
import logging
import shutil
from collections.abc import Generator

from ._resourcePath import ResourcePath
from .file import FileResourcePath

log = logging.getLogger(__name__)


class RemoteTestResourcePath(FileResourcePath):
    """A local file resource path that pretends it is a remote resource."""

    # By definition a remote file.
    isLocal = False

    @contextlib.contextmanager
    def _as_local(
        self, multithreaded: bool = True, tmpdir: ResourcePath | None = None
    ) -> Generator[ResourcePath, None, None]:
        """Copy file to a new location in a temporary directory.

        Parameters
        ----------
        multithreaded : `bool`, optional
            Unused.
        tmpdir : `ResourcePath` or `None`, optional
            Explicit override of the temporary directory to use for remote
            downloads.

        Returns
        -------
        local_uri : `ResourcePath`
            A URI to a local POSIX file corresponding to a local temporary
            downloaded copy of the resource.
        """
        with (
            ResourcePath.temporary_uri(prefix=tmpdir, suffix=self.getExtension(), delete=True) as tmp_uri,
        ):
            shutil.copy(self.ospath, tmp_uri.ospath)
            yield tmp_uri
