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

__all__ = ("BaseResourceHandle", "CloseStatus")

from abc import ABC, abstractmethod, abstractproperty
from io import SEEK_SET
from logging import Logger
from typing import Iterable, TypeVar, Union, Optional
from enum import Enum, auto

T = TypeVar('T', bound="BaseResourceHandle")


class CloseStatus(Enum):
    OPEN = auto()
    CLOSING = auto()
    CLOSED = auto()


class BaseResourceHandle(ABC):
    """Base class interface for the handle like interface of `ResourcePath`
    subclasses.

    Parameters
    ----------
    mode : `str`
        Handle modes as described in the python `io` module
    log : `~logging.Logger`
        Logger to used when writing messages
    lineseperator : `str`
        When doing multiline operations, break the stream on given character

    Notes
    -----
    Documentation on the methods of this class line should refer to the
    corresponding methods in the `io` module.
    """
    _closed: CloseStatus
    _mode: str
    _lineseperator: bytes
    _log: Logger

    def __init__(self, mode, log, *, newline: Union[str, bytes] = '\n'):
        self._mode = mode
        self._log = log
        self._newline = newline

    @property
    def mode(self) -> str:
        return self._mode

    @abstractmethod
    def close(self):
        ...

    @abstractproperty
    def closed(self) -> bool:
        ...

    @abstractmethod
    def fileno(self) -> int:
        ...

    @abstractmethod
    def flush(self) -> None:
        ...

    @abstractproperty
    def isatty(self) -> bool:
        ...

    @abstractmethod
    def readable(self) -> bool:
        ...

    @abstractmethod
    def readline(self, size: int = -1) -> bytes:
        ...

    @abstractmethod
    def readlines(self, hint: int = -1) -> Iterable[bytes]:
        ...

    @abstractmethod
    def seek(self, offset: int, whence: int = SEEK_SET) -> None:
        ...

    @abstractmethod
    def seekable(self) -> bool:
        ...

    @abstractmethod
    def tell(self) -> int:
        ...

    @abstractmethod
    def truncate(self, size: Optional[int] = None) -> None:
        ...

    @abstractmethod
    def writable(self) -> bool:
        ...

    @abstractmethod
    def writelines(self, lines) -> None:
        ...

    @abstractmethod
    def read(self, size=-1) -> bytes:
        ...

    @abstractmethod
    def readall(self) -> bytes:
        ...

    @abstractmethod
    def readinto(self, b) -> int:
        ...

    @abstractmethod
    def write(self, b: Union[bytes, str]) -> None:
        ...

    def __enter__(self: T) -> T:
        self._closed = CloseStatus.OPEN
        return self

    def __exit__(self, exc_type, exc_bal, exc_tb) -> None:
        self.close()
