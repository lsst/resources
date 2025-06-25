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

__all__ = ("EupsResourcePath",)

import logging
import posixpath
import urllib.parse

from lsst.utils import getPackageDir

from ._resourcePath import ResourcePath
from .file import FileResourcePath
from .utils import os2posix

log = logging.getLogger(__name__)


class EupsResourcePath(FileResourcePath):
    """URI referring to an EUPS package.

    These URIs look like: ``eups://daf_butler/configs/file.yaml``
    where the network location is the EUPS package name.

    An EUPS resource path is transitory since it always becomes a file
    URI.
    """

    @classmethod
    def _fixupPathUri(
        cls,
        parsed: urllib.parse.ParseResult,
        root: ResourcePath | None = None,
        forceAbsolute: bool = False,
        forceDirectory: bool | None = None,
    ) -> tuple[urllib.parse.ParseResult, bool | None]:
        """Fix up relative paths for local file system.

        Parameters
        ----------
        parsed : `~urllib.parse.ParseResult`
            The result from parsing a URI using `urllib.parse`.
        root : `ResourcePath`, optional
            Path to use as root when converting relative to absolute.
            If `None`, it will be the current working directory. Will be
            ignored if the supplied path is already absolute or if
            ``forceAbsolute`` is `False`.
        forceAbsolute : `bool`, optional
            If `True`, scheme-less relative URI will be converted to an
            absolute path using a ``file`` scheme. If `False` scheme-less URI
            will remain scheme-less and will not be updated to ``file`` or
            absolute path.
        forceDirectory : `bool`, optional
            If `True` forces the URI to end with a separator, otherwise given
            URI is interpreted as is. `False` can be used to indicate that
            the URI is known to correspond to a file. `None` means that the
            status is unknown.

        Returns
        -------
        modified : `~urllib.parse.ParseResult`
            Update result if a URI is being handled.
        dirLike : `bool`
            `True` if given parsed URI has a trailing separator or
            forceDirectory is True. Otherwise `False`.

        Notes
        -----
        Relative paths are explicitly not supported by RFC8089 but `urllib`
        does accept URIs of the form ``file:relative/path.ext``. They need
        to be turned into absolute paths before they can be used.  This is
        always done regardless of the ``forceAbsolute`` parameter.

        Scheme-less paths are normalized and environment variables are
        expanded.
        """
        # getPackageDir returns an absolute path.
        eups_path = getPackageDir(parsed.netloc)
        print(parsed)
        print(eups_path)
        print(os2posix(eups_path))
        new_path = posixpath.join(os2posix(eups_path), os2posix(parsed.path.lstrip("/")))
        print("New path: ", new_path)
        parsed = parsed._replace(path=urllib.parse.quote(new_path), scheme="file", netloc="")

        return super()._fixupPathUri(parsed, root, forceAbsolute=forceAbsolute, forceDirectory=forceDirectory)
