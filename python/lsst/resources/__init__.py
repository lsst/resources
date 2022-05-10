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


"""ResourcePath is a package for abstracting access to local or remote files."""

from ._resourceHandles import ResourceHandleProtocol

# Should only expose ResourcePath and its input type alias
from ._resourcePath import ResourcePath, ResourcePathExpression
from .version import *
