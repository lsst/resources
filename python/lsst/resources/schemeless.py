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

__all__ = ("SchemelessResourcePath",)

import logging
import os
import os.path
import urllib.parse
from pathlib import PurePath

from ._resourcePath import ResourcePath
from .file import FileResourcePath
from .utils import os2posix

log = logging.getLogger(__name__)


class SchemelessResourcePath(FileResourcePath):
    """Scheme-less URI referring to the local file system or relative URI."""

    _pathLib = PurePath
    _pathModule = os.path
    quotePaths = False

    @property
    def ospath(self) -> str:
        """Path component of the URI localized to current OS."""
        return self.path

    def isabs(self) -> bool:
        """Indicate that the resource is fully specified.

        For non-schemeless URIs this is always true.

        Returns
        -------
        isabs : `bool`
            `True` if the file is absolute, `False` otherwise.
        """
        return os.path.isabs(self.ospath)

    def abspath(self) -> ResourcePath:
        """Force a schemeless URI to a file URI.

        This will include URI quoting of the path.

        Returns
        -------
        file : `FileResourcePath`
            A new URI using file scheme.

        Notes
        -----
        The current working directory will be used to convert this scheme-less
        URI to an absolute path.
        """
        # Convert this URI to a string so that any fragments will be
        # processed correctly by the ResourcePath constructor.  We provide
        # the options that will force the code below in _fixupPathUri to
        # return a file URI from a scheme-less one.
        return ResourcePath(
            str(self), forceAbsolute=True, forceDirectory=self.isdir(), isTemporary=self.isTemporary
        )

    def relative_to(self, other: ResourcePath) -> str | None:
        """Return the relative path from this URI to the other URI.

        Parameters
        ----------
        other : `ResourcePath`
            URI to use to calculate the relative path.

        Returns
        -------
        subpath : `str`
            The sub path of this URI relative to the supplied other URI.
            Returns `None` if there is no parent child relationship.
            If this URI is a relative URI but the other is
            absolute, it is assumed to be in the parent completely unless it
            starts with ".." (in which case the path is combined and tested).
            If both URIs are relative, the relative paths are compared
            for commonality.

        Notes
        -----
        By definition a relative path will be relative to the enclosing
        absolute parent URI. It will be returned unchanged if it does not
        use a parent directory specification.
        """
        # In some scenarios below a new derived child URI needs to be created
        # to convert from scheme-less to absolute URI.
        child = None

        if not self.isabs() and not other.isabs():
            # Both are schemeless relative. Use parent implementation
            # rather than trying to convert both to file: first since schemes
            # match.
            pass
        elif not self.isabs() and other.isabs():
            # Append child to other. This can account for .. in child path.
            child = other.join(self.path)
        elif self.isabs() and not other.isabs():
            # Finding common paths is not possible if the parent is
            # relative and the child is absolute.
            return None
        elif self.isabs() and other.isabs():
            # Both are absolute so convert schemeless to file
            # if necessary.
            child = self.abspath()
            if not other.scheme:
                other = other.abspath()
        else:
            raise RuntimeError(f"Unexpected combination of {child}.relative_to({other}).")

        if child is None:
            return super().relative_to(other)
        return child.relative_to(other)

    @classmethod
    def _fixupPathUri(
        cls,
        parsed: urllib.parse.ParseResult,
        root: ResourcePath | None = None,
        forceAbsolute: bool = False,
        forceDirectory: bool = False,
    ) -> tuple[urllib.parse.ParseResult, bool]:
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
            URI is interpreted as is.

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
        # assume we are not dealing with a directory URI
        dirLike = False

        # Replacement values for the URI
        replacements = {}

        # this is a local OS file path which can support tilde expansion.
        # we quoted it in the constructor so unquote here
        expandedPath = os.path.expanduser(urllib.parse.unquote(parsed.path))

        # We might also be receiving a path containing environment variables
        # so expand those here
        expandedPath = os.path.expandvars(expandedPath)

        # Ensure that this becomes a file URI if it is already absolute
        if os.path.isabs(expandedPath):
            replacements["scheme"] = "file"
            # Keep in OS form for now to simplify later logic
            replacements["path"] = os.path.normpath(expandedPath)
        elif forceAbsolute:
            # Need to know the root that should be prepended.
            if root is None:
                root_str = os.path.abspath(os.path.curdir)
            else:
                if root.scheme and root.scheme != "file":
                    raise ValueError(f"The override root must be a file URI not {root.scheme}")
                # os.path does not care whether something is dirLike or not
                # so we trust the user.
                root_str = os.path.abspath(root.ospath)

            # Convert to "file" scheme to make it consistent with the above
            # decision. It makes no sense for sometimes an absolute path
            # to be a file URI and sometimes for it not to be.
            replacements["scheme"] = "file"

            # Keep in OS form for now.
            replacements["path"] = os.path.normpath(os.path.join(root_str, expandedPath))
        else:
            # No change needed for relative local path staying relative
            # except normalization
            replacements["path"] = os.path.normpath(expandedPath)
            # normalization of empty path returns "." so we are dirLike
            if expandedPath == "":
                dirLike = True

        # normpath strips trailing "/" which makes it hard to keep
        # track of directory vs file when calling replaceFile

        # For local file system we can explicitly check to see if this
        # really is a directory. The URI might point to a location that
        # does not exists yet but all that matters is if it is a directory
        # then we make sure use that fact. No need to do the check if
        # we are already being told.
        if not forceDirectory and os.path.isdir(replacements["path"]):
            forceDirectory = True

        # add the trailing separator only if explicitly required or
        # if it was stripped by normpath. Acknowledge that trailing
        # separator exists.
        endsOnSep = expandedPath.endswith(os.sep) and not replacements["path"].endswith(os.sep)
        if forceDirectory or endsOnSep or dirLike:
            dirLike = True
            if not replacements["path"].endswith(os.sep):
                replacements["path"] += os.sep

        if "scheme" in replacements:
            # This is now meant to be a URI path so force to posix
            # and quote
            replacements["path"] = urllib.parse.quote(os2posix(replacements["path"]))

        # ParseResult is a NamedTuple so _replace is standard API
        parsed = parsed._replace(**replacements)

        # We do allow fragment but do not expect params or query to be
        # specified for schemeless
        if parsed.params or parsed.query:
            log.warning("Additional items unexpectedly encountered in schemeless URI: %s", parsed.geturl())

        return parsed, dirLike
