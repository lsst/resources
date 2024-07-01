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

from types import TracebackType

__all__ = ("BaseResourceHandle", "CloseStatus", "ResourceHandleProtocol")

import logging
from abc import ABC, abstractmethod, abstractproperty
from collections.abc import Callable, Iterable
from enum import Enum, auto
from io import SEEK_SET
from typing import TYPE_CHECKING, AnyStr, Generic, Protocol, TypeVar

if TYPE_CHECKING:
    # Circular import.
    from .._resourcePath import ResourcePath

S = TypeVar("S", bound="ResourceHandleProtocol")
T = TypeVar("T", bound="BaseResourceHandle")
U = TypeVar("U", str, bytes)


class CloseStatus(Enum):
    """Enumerated closed/open status of a file handle, implementation detail
    that may be used by BaseResourceHandle children.
    """

    OPEN = auto()
    CLOSING = auto()
    CLOSED = auto()


class ResourceHandleProtocol(Protocol, Generic[U]):
    """Defines the interface protocol that is compatible with children of
    `.BaseResourceHandle`.

    Any class that satisfies this protocol can be used in any context where a
    `.BaseResourceHandle` is expected.
    """

    @abstractproperty
    def mode(self) -> str: ...

    @abstractproperty
    def name(self) -> str: ...

    @abstractmethod
    def close(self) -> None: ...

    @abstractproperty
    def closed(self) -> bool: ...

    @abstractmethod
    def fileno(self) -> int: ...

    @abstractmethod
    def flush(self) -> None: ...

    @abstractproperty
    def isatty(self) -> bool | Callable[[], bool]: ...

    @abstractmethod
    def readable(self) -> bool: ...

    @abstractmethod
    def readline(self, size: int = -1) -> U: ...

    @abstractmethod
    def readlines(self, hint: int = -1) -> Iterable[U]: ...

    @abstractmethod
    def seek(self, offset: int, whence: int = SEEK_SET, /) -> int:
        pass

    @abstractmethod
    def seekable(self) -> bool: ...

    @abstractmethod
    def tell(self) -> int: ...

    @abstractmethod
    def truncate(self, size: int | None = None) -> int: ...

    @abstractmethod
    def writable(self) -> bool: ...

    @abstractmethod
    def writelines(self, lines: Iterable[U], /) -> None: ...

    @abstractmethod
    def read(self, size: int = -1) -> U: ...

    @abstractmethod
    def write(self, b: U, /) -> int: ...

    def __enter__(self: S) -> S: ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
        /,
    ) -> bool | None: ...


class BaseResourceHandle(ABC, ResourceHandleProtocol[U]):
    """Base class interface for the handle like interface of
    `~lsst.resources.ResourcePath` subclasses.

    Parameters
    ----------
    mode : `str`
        Handle modes as described in the python `io` module.
    log : `~logging.Logger`
        Logger to used when writing messages.
    uri : `lsst.resources.ResourcePath`
        The URI of the resource being opened.
    newline : `str`
        When doing multiline operations, break the stream on given character
        Defaults to newline.

    Notes
    -----
    Documentation on the methods of this class line should refer to the
    corresponding methods in the `io` module.
    """

    _closed: CloseStatus
    _mode: str
    _log: logging.Logger
    _newline: U
    _uri: ResourcePath

    def __init__(
        self, mode: str, log: logging.Logger, uri: ResourcePath, *, newline: AnyStr | None = None
    ) -> None:
        if newline is None:
            if "b" in mode:
                self._newline = b"\n"  # type: ignore
            else:
                self._newline = "\n"  # type: ignore
        else:
            self._newline = newline  # type: ignore
        self._mode = mode
        self._log = log
        self._uri = uri

    @property
    def name(self) -> str:
        # Use name for compatibility with TextIOWrapper.
        return str(self._uri)

    @property
    def mode(self) -> str:
        return self._mode

    def __enter__(self: T) -> T:
        self._closed = CloseStatus.OPEN
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_bal: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> bool | None:
        self.close()
        return None
