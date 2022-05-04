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
import copy
import logging
import os
import os.path
import posixpath
import re
import shutil
import urllib.parse

__all__ = ("FileResourcePath",)

from typing import IO, TYPE_CHECKING, Iterator, List, Optional, Tuple, Union

from ._resourceHandles._fileResourceHandle import FileResourceHandle
from ._resourcePath import ResourcePath
from .utils import NoTransaction, os2posix, posix2os

if TYPE_CHECKING:
    from .utils import TransactionProtocol


log = logging.getLogger(__name__)


class FileResourcePath(ResourcePath):
    """Path for explicit ``file`` URI scheme."""

    transferModes = ("copy", "link", "symlink", "hardlink", "relsymlink", "auto", "move")
    transferDefault: str = "link"

    # By definition refers to a local file
    isLocal = True

    @property
    def ospath(self) -> str:
        """Path component of the URI localized to current OS.

        Will unquote URI path since a formal URI must include the quoting.
        """
        return urllib.parse.unquote(posix2os(self._uri.path))

    def exists(self) -> bool:
        """Indicate that the file exists."""
        # Uses os.path.exists so if there is a soft link that points
        # to a file that no longer exists this will return False
        return os.path.exists(self.ospath)

    def size(self) -> int:
        """Return the size of the file in bytes."""
        if not os.path.isdir(self.ospath):
            stat = os.stat(self.ospath)
            sz = stat.st_size
        else:
            sz = 0
        return sz

    def remove(self) -> None:
        """Remove the resource."""
        os.remove(self.ospath)

    def _as_local(self) -> Tuple[str, bool]:
        """Return the local path of the file.

        This is an internal helper for ``as_local()``.

        Returns
        -------
        path : `str`
            The local path to this file.
        temporary : `bool`
            Always returns the temporary nature of the input file resource.
        """
        return self.ospath, self.isTemporary

    def read(self, size: int = -1) -> bytes:
        """Return the entire content of the file as bytes."""
        with open(self.ospath, "rb") as fh:
            return fh.read(size)

    def write(self, data: bytes, overwrite: bool = True) -> None:
        """Write the supplied data to the file."""
        dir = os.path.dirname(self.ospath)
        if not os.path.exists(dir):
            os.makedirs(dir, exist_ok=True)
        if overwrite:
            mode = "wb"
        else:
            mode = "xb"
        with open(self.ospath, mode) as f:
            f.write(data)

    def mkdir(self) -> None:
        """Make the directory associated with this URI.

        An attempt will be made to create the directory even if the URI
        looks like a file.

        Raises
        ------
        NotADirectoryError:
            Raised if a non-directory already exists.
        """
        try:
            os.makedirs(self.ospath, exist_ok=True)
        except FileExistsError:
            raise NotADirectoryError(f"{self.ospath} exists but is not a directory.") from None

    def isdir(self) -> bool:
        """Return whether this URI is a directory.

        Returns
        -------
        isdir : `bool`
            `True` if this URI is a directory or looks like a directory,
            else `False`.
        """
        return self.dirLike or os.path.isdir(self.ospath)

    def transfer_from(
        self,
        src: ResourcePath,
        transfer: str,
        overwrite: bool = False,
        transaction: Optional[TransactionProtocol] = None,
    ) -> None:
        """Transfer the current resource to a local file.

        Parameters
        ----------
        src : `ResourcePath`
            Source URI.
        transfer : `str`
            Mode to use for transferring the resource. Supports the following
            options: copy, link, symlink, hardlink, relsymlink.
        overwrite : `bool`, optional
            Allow an existing file to be overwritten. Defaults to `False`.
        transaction : `~lsst.resources.utils.TransactionProtocol`, optional
            If a transaction is provided, undo actions will be registered.
        """
        # Fail early to prevent delays if remote resources are requested
        if transfer not in self.transferModes:
            raise ValueError(f"Transfer mode '{transfer}' not supported by URI scheme {self.scheme}")

        # Existence checks can take time so only try if the log message
        # will be issued.
        if log.isEnabledFor(logging.DEBUG):
            log.debug(
                "Transferring %s [exists: %s] -> %s [exists: %s] (transfer=%s)",
                src,
                src.exists(),
                self,
                self.exists(),
                transfer,
            )

        # We do not have to special case FileResourcePath here because
        # as_local handles that.
        with src.as_local() as local_uri:
            is_temporary = local_uri.isTemporary
            local_src = local_uri.ospath

            # Short circuit if the URIs are identical immediately.
            if self == local_uri:
                log.debug(
                    "Target and destination URIs are identical: %s, returning immediately."
                    " No further action required.",
                    self,
                )
                return

            # Default transfer mode depends on whether we have a temporary
            # file or not.
            if transfer == "auto":
                transfer = self.transferDefault if not is_temporary else "copy"

            if not os.path.exists(local_src):
                if is_temporary:
                    if src == local_uri:
                        msg = f"Local temporary file {src} has gone missing."
                    else:
                        # This will not happen in normal scenarios.
                        msg = f"Local file {local_uri} downloaded from {src} has gone missing"
                else:
                    msg = f"Source URI {src} does not exist"
                raise FileNotFoundError(msg)

            # Follow soft links
            local_src = os.path.realpath(os.path.normpath(local_src))

            # Creating a symlink to a local copy of a remote resource
            # should never work. Creating a hardlink will work but should
            # not be allowed since it is highly unlikely that this is ever
            # an intended option and depends on the local target being
            # on the same file system as was used for the temporary file
            # download.
            # If a symlink is being requested for a local temporary file
            # that is likely undesirable but should not be refused.
            if is_temporary and src != local_uri and "link" in transfer:
                raise RuntimeError(
                    f"Can not use local file system transfer mode {transfer} for remote resource ({src})"
                )
            elif is_temporary and src == local_uri and "symlink" in transfer:
                log.debug(
                    "Using a symlink for a temporary resource may lead to unexpected downstream failures."
                )

            # For temporary files we can own them if we created it.
            requested_transfer = transfer
            if src != local_uri and is_temporary and transfer == "copy":
                transfer = "move"

            # The output location should not exist unless overwrite=True.
            # Rather than use `exists()`, use os.stat since we might need
            # the full answer later.
            dest_stat: Optional[os.stat_result]
            try:
                # Do not read through links of the file itself.
                dest_stat = os.lstat(self.ospath)
            except FileNotFoundError:
                dest_stat = None

            # It is possible that the source URI and target URI refer
            # to the same file. This can happen for a number of reasons
            # (such as soft links in the path, or they really are the same).
            # In that case log a message and return as if the transfer
            # completed (it technically did). A temporary file download
            # can't be the same so the test can be skipped.
            if dest_stat and not is_temporary:
                # Be consistent and use lstat here (even though realpath
                # has been called). It does not harm.
                local_src_stat = os.lstat(local_src)
                if dest_stat.st_ino == local_src_stat.st_ino and dest_stat.st_dev == local_src_stat.st_dev:
                    log.debug(
                        "Destination URI %s is the same file as source URI %s, returning immediately."
                        " No further action required.",
                        self,
                        local_uri,
                    )
                    return

            if not overwrite and dest_stat:
                raise FileExistsError(
                    f"Destination path '{self}' already exists. Transfer from {src} cannot be completed."
                )

            # Make the path absolute (but don't follow links since that
            # would possibly cause us to end up in the wrong place if the
            # file existed already as a soft link)
            newFullPath = os.path.abspath(self.ospath)
            outputDir = os.path.dirname(newFullPath)
            if not os.path.isdir(outputDir):
                # Must create the directory -- this can not be rolled back
                # since another transfer running concurrently may
                # be relying on this existing.
                os.makedirs(outputDir, exist_ok=True)

            if transaction is None:
                # Use a no-op transaction to reduce code duplication
                transaction = NoTransaction()

            # For links the OS doesn't let us overwrite so if something does
            # exist we have to remove it before we do the actual "transfer"
            # below
            if "link" in transfer and overwrite and dest_stat:
                try:
                    self.remove()
                except Exception:
                    # If this fails we ignore it since it's a problem
                    # that will manifest immediately below with a more relevant
                    # error message
                    pass

            if transfer == "move":
                # If a rename works we try that since that is guaranteed to
                # be atomic. If that fails we copy and rename. We do this
                # in case other processes are trying to move to the same
                # file and we want the "winner" to not be corrupted.
                try:
                    with transaction.undoWith(f"move from {local_src}", os.rename, newFullPath, local_src):
                        os.rename(local_src, newFullPath)
                except OSError:
                    with self.temporary_uri(prefix=self.parent(), suffix=self.getExtension()) as temp_copy:
                        shutil.copy(local_src, temp_copy.ospath)
                        with transaction.undoWith(
                            f"move from {local_src}",
                            shutil.move,
                            newFullPath,
                            local_src,
                            copy_function=shutil.copy,
                        ):
                            os.rename(temp_copy.ospath, newFullPath)
                    os.remove(local_src)
            elif transfer == "copy":
                # We want atomic copies so first copy to a temp location in
                # the same output directory. This at least guarantees that
                # if multiple processes are writing to the same file
                # simultaneously the file we end up with will not be corrupt.
                with self.temporary_uri(prefix=self.parent(), suffix=self.getExtension()) as temp_copy:
                    shutil.copy(local_src, temp_copy.ospath)
                    with transaction.undoWith(f"copy from {local_src}", os.remove, newFullPath):
                        # os.rename works even if the file exists.
                        # It's possible that another process has copied a file
                        # in whilst this one was copying. If overwrite
                        # protection is needed then another stat() call should
                        # happen here.
                        os.rename(temp_copy.ospath, newFullPath)
            elif transfer == "link":
                # Try hard link and if that fails use a symlink
                with transaction.undoWith(f"link to {local_src}", os.remove, newFullPath):
                    try:
                        os.link(local_src, newFullPath)
                    except OSError:
                        # Read through existing symlinks
                        os.symlink(local_src, newFullPath)
            elif transfer == "hardlink":
                with transaction.undoWith(f"hardlink to {local_src}", os.remove, newFullPath):
                    os.link(local_src, newFullPath)
            elif transfer == "symlink":
                # Read through existing symlinks
                with transaction.undoWith(f"symlink to {local_src}", os.remove, newFullPath):
                    os.symlink(local_src, newFullPath)
            elif transfer == "relsymlink":
                # This is a standard symlink but using a relative path
                # Need the directory name to give to relative root
                # A full file path confuses it into an extra ../
                newFullPathRoot = os.path.dirname(newFullPath)
                relPath = os.path.relpath(local_src, newFullPathRoot)
                with transaction.undoWith(f"relsymlink to {local_src}", os.remove, newFullPath):
                    os.symlink(relPath, newFullPath)
            else:
                raise NotImplementedError("Transfer type '{}' not supported.".format(transfer))

            # This was an explicit move requested from a remote resource
            # try to remove that remote resource. We check is_temporary because
            # the local file would have been moved by shutil.move already.
            if requested_transfer == "move" and is_temporary and src != local_uri:
                # Transactions do not work here
                src.remove()

    def walk(
        self, file_filter: Optional[Union[str, re.Pattern]] = None
    ) -> Iterator[Union[List, Tuple[ResourcePath, List[str], List[str]]]]:
        """Walk the directory tree returning matching files and directories.

        Parameters
        ----------
        file_filter : `str` or `re.Pattern`, optional
            Regex to filter out files from the list before it is returned.

        Yields
        ------
        dirpath : `ResourcePath`
            Current directory being examined.
        dirnames : `list` of `str`
            Names of subdirectories within dirpath.
        filenames : `list` of `str`
            Names of all the files within dirpath.
        """
        if not self.isdir():
            raise ValueError("Can not walk a non-directory URI")

        if isinstance(file_filter, str):
            file_filter = re.compile(file_filter)

        for root, dirs, files in os.walk(self.ospath, followlinks=True):
            # Filter by the regex
            if file_filter is not None:
                files = [f for f in files if file_filter.search(f)]
            yield type(self)(root, forceAbsolute=False, forceDirectory=True), dirs, files

    @classmethod
    def _fixupPathUri(
        cls,
        parsed: urllib.parse.ParseResult,
        root: Optional[Union[str, ResourcePath]] = None,
        forceAbsolute: bool = False,
        forceDirectory: bool = False,
    ) -> Tuple[urllib.parse.ParseResult, bool]:
        """Fix up relative paths in URI instances.

        Parameters
        ----------
        parsed : `~urllib.parse.ParseResult`
            The result from parsing a URI using `urllib.parse`.
        root : `str` or `ResourcePath`, optional
            Path to use as root when converting relative to absolute.
            If `None`, it will be the current working directory. This
            is a local file system path, or a file URI.  It is only used if
            a file-scheme is used incorrectly with a relative path.
        forceAbsolute : `bool`, ignored
            Has no effect for this subclass. ``file`` URIs are always
            absolute.
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
        """
        # assume we are not dealing with a directory like URI
        dirLike = False

        # file URI implies POSIX path separators so split as POSIX,
        # then join as os, and convert to abspath. Do not handle
        # home directories since "file" scheme is explicitly documented
        # to not do tilde expansion.
        sep = posixpath.sep

        # For local file system we can explicitly check to see if this
        # really is a directory. The URI might point to a location that
        # does not exists yet but all that matters is if it is a directory
        # then we make sure use that fact. No need to do the check if
        # we are already being told.
        if not forceDirectory and posixpath.isdir(parsed.path):
            forceDirectory = True

        # For an absolute path all we need to do is check if we need
        # to force the directory separator
        if posixpath.isabs(parsed.path):
            if forceDirectory:
                if not parsed.path.endswith(sep):
                    parsed = parsed._replace(path=parsed.path + sep)
                dirLike = True
            return copy.copy(parsed), dirLike

        # Relative path so must fix it to be compliant with the standard

        # Replacement values for the URI
        replacements = {}

        if root is None:
            root = os.path.abspath(os.path.curdir)
        elif isinstance(root, ResourcePath):
            if root.scheme and root.scheme != "file":
                raise RuntimeError(f"The override root must be a file URI not {root.scheme}")
            root = os.path.abspath(root.ospath)

        replacements["path"] = posixpath.normpath(posixpath.join(os2posix(root), parsed.path))

        # normpath strips trailing "/" so put it back if necessary
        # Acknowledge that trailing separator exists.
        if forceDirectory or (parsed.path.endswith(sep) and not replacements["path"].endswith(sep)):
            replacements["path"] += sep
            dirLike = True

        # ParseResult is a NamedTuple so _replace is standard API
        parsed = parsed._replace(**replacements)

        if parsed.params or parsed.query:
            log.warning("Additional items unexpectedly encountered in file URI: %s", parsed.geturl())

        return parsed, dirLike

    @contextlib.contextmanager
    def _openImpl(
        self,
        mode: str = "r",
        *,
        encoding: Optional[str] = None,
    ) -> Iterator[IO]:
        with FileResourceHandle(mode=mode, log=log, filename=self.ospath, encoding=encoding) as buffer:
            yield buffer  # type: ignore
