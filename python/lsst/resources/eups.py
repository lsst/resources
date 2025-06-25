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
from .proxied import ProxiedResourcePath
from .utils import os2posix

log = logging.getLogger(__name__)


class EupsResourcePath(ProxiedResourcePath):
    """URI referring to an EUPS package.

    These URIs look like: ``eups://daf_butler/configs/file.yaml``
    where the network location is the EUPS package name.

    Internally they are proxied by either ``file`` URIs or ``resource`` URIs.
    If an ``{product}_DIR`` environment variable is found it will be used
    and internally a ``file`` URI will be created. If no environment variable
    is found an attempt will be made to convert the EUPS product name to
    a python package and a ``resource`` URI will be returned with
    ``/resources`` appended. The convention is that any package supporting
    an EUPS URI outside an EUPS environment will also have made available
    the support files as package resources.

    If it is known that the package supports package resources it is always
    better to use that URI form explicitly since it is more robust since
    not all EUPS packages can reliably be converted to python packages
    without EUPS.
    """

    quotePaths = False
    _proxy: ResourcePath | None = None
    _default_namespace: str = "lsst"

    def _set_proxy(self) -> None:
        """Calculate the internal `ResourcePath` corresponding to the public
        version.
        """
        # getPackageDir returns an absolute path.
        try:
            eups_path = getPackageDir(self.netloc)
            log.debug("Found EUPS package %s via env var", self.netloc)
        except LookupError:
            eups_path = ""
        if eups_path:
            # Must convert this path into a file URI.
            new_path = posixpath.join(os2posix(eups_path), os2posix(self.path.lstrip("/")))
            parsed = self._uri._replace(path=urllib.parse.quote(new_path), scheme="file", netloc="")
            self._proxy = ResourcePath(parsed)
            return

        # If there is no _DIR env var we need to look for python package
        # resource. There is no guaranteed way to generated a python package
        # from an EUPS product name.
        # daf_butler -> lsst.daf.butler
        # image_cutout_backend -> lsst.image_cutout_backend
        # astro_metadata_translator -> astro_metadata_translator
        product = self.netloc
        variants = (
            product,
            self._default_namespace + "." + product.replace("_", "."),
            self._default_namespace + "." + product,
            product.replace("_", "."),
        )
        for variant in variants:
            proxy = ResourcePath(f"resource://{variant}/resources", forceDirectory=True)
            # This can be slow because package imports happen but there is
            # no other way to check that we have the correct variant.
            log.debug("Trying variant %s", proxy)
            if proxy.exists():
                self._proxy = proxy
                if self.path:
                    self._proxy = self._proxy.join(self.path.lstrip("/"))
                log.debug(f"Found variant {variant}")
                return

        # Can not find an actively set up package or resources for this EUPS
        # product. Return without setting a proxy to allow standard URI
        # path manipulations to happen but defer failure until someone tries
        # to use the proxy for read.
        log.debug("Could not find any files corresponding to %s", self)
        return
