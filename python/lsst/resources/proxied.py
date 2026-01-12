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

__all__ = ("ProxiedResourcePath",)

import contextlib
import logging
import re
from abc import ABC, abstractmethod
from collections.abc import Iterator

from ._resourcePath import ResourceHandleProtocol, ResourcePath, ResourcePathExpression
from .utils import TransactionProtocol

try:
    import fsspec
    from fsspec.spec import AbstractFileSystem
except ImportError:
    fsspec = None
    AbstractFileSystem = type


log = logging.getLogger(__name__)


class ProxiedResourcePath(ABC, ResourcePath):
    """URI that is represented internally by another type of URI for file I/O.

    For example ``abc://xyz/file.txt`` could be the public URI form but
    internally all file access is forwarded to a ``file`` URI.
    """

    _proxy: ResourcePath | None = None

    @abstractmethod
    def _set_proxy(self) -> None:
        """Calculate the internal `ResourcePath` corresponding to the public
        version.
        """
        raise NotImplementedError("Proxy must be configured")

    def _get_proxy(self) -> ResourcePath:
        """Retrieve the proxied ResourcePath."""
        proxy = self._proxy
        if proxy is None:
            raise FileNotFoundError(f"Internal error: No proxy ResourcePath available for {self}")
        return proxy

    def to_fsspec(self) -> tuple[AbstractFileSystem, str]:
        try:
            proxy = self._get_proxy()
        except FileNotFoundError:
            raise NotImplementedError(f"No proxy registered for {self}. Resource does not exist.") from None
        return proxy.to_fsspec()

    def isdir(self) -> bool:
        if self.dirLike is None:
            try:
                proxy = self._get_proxy()
            except FileNotFoundError:
                return False
            self.dirLike = proxy.isdir()
        return self.dirLike

    def exists(self) -> bool:
        try:
            proxy = self._get_proxy()
        except FileNotFoundError:
            # If there is no proxy registered then the resource can not exist.
            return False
        return proxy.exists()

    def remove(self) -> None:
        proxy = self._get_proxy()
        proxy.remove()

    def read(self, size: int = -1) -> bytes:
        proxy = self._get_proxy()
        return proxy.read(size=size)

    @contextlib.contextmanager
    def as_local(
        self, multithreaded: bool = True, tmpdir: ResourcePathExpression | None = None
    ) -> Iterator[ResourcePath]:
        proxy = self._get_proxy()
        with proxy.as_local(multithreaded=multithreaded, tmpdir=tmpdir) as loc:
            yield loc

    @contextlib.contextmanager
    def open(
        self,
        mode: str = "r",
        *,
        encoding: str | None = None,
        prefer_file_temporary: bool = False,
    ) -> Iterator[ResourceHandleProtocol]:
        proxy = self._get_proxy()
        with proxy.open(mode, encoding=encoding, prefer_file_temporary=prefer_file_temporary) as fh:
            yield fh

    def walk(
        self, file_filter: str | re.Pattern | None = None
    ) -> Iterator[list | tuple[ResourcePath, list[str], list[str]]]:
        try:
            proxy = self._get_proxy()
        except FileNotFoundError as e:
            raise ValueError(str(e)) from None
        for proxied_root, dirs, files in proxy.walk(file_filter=file_filter):
            # Need to return the directory in the original form and not the
            # proxy form.
            relative_to_self = proxied_root.path.removeprefix(proxy.path)
            root = self.replace(path=self._pathModule.join(self.path, relative_to_self))
            yield root, dirs, files

    def size(self) -> int:
        proxy = self._get_proxy()
        return proxy.size()

    def write(self, data: bytes, overwrite: bool = True) -> None:
        proxy = self._get_proxy()
        proxy.write(data, overwrite=overwrite)

    def mkdir(self) -> None:
        proxy = self._get_proxy()
        proxy.mkdir()

    def transfer_from(
        self,
        src: ResourcePath,
        transfer: str = "copy",
        overwrite: bool = False,
        transaction: TransactionProtocol | None = None,
        multithreaded: bool = True,
    ) -> None:
        proxy = self._get_proxy()
        proxy.transfer_from(
            src, transfer=transfer, overwrite=overwrite, transaction=transaction, multithreaded=multithreaded
        )
