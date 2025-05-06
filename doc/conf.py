"""Sphinx configuration file for an LSST stack package.

This configuration only affects single-package Sphinx documenation builds.
"""

from documenteer.conf.pipelinespkg import *  # noqa: F403, import *

project = "resources"
html_theme_options["logotext"] = project  # noqa: F405, unknown name
html_title = project
html_short_title = project
doxylink = {}
exclude_patterns = ["changes/*"]

intersphinx_mapping["fsspec"] = ("https://filesystem-spec.readthedocs.io/en/latest/", None)  # noqa: F405

nitpick_ignore_regex = [
    ("py:(class|obj)", ".*ResourceHandle.U$"),
    ("py:(class|obj)", "re.Pattern"),
    ("py:(class|obj)", ".*MBulkResult$"),
    ("py:(class|obj)", ".*ResourcePathExpression$"),
]
nitpick_ignore = [
    ("py:obj", "lsst.daf.butler.core.datastore.DatastoreTransaction"),
]
