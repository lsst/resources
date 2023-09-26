Resources v26.0.0 2023-09-22
============================

This package now requires Python 3.10 and newer.

New Features
------------

- ``resource`` URI schemes now use `importlib.resources` (or ``importlib_resources``) rather than the deprecated ``pkg_resources``.
  Due to this change, ``resource`` URI schemes now also support ``walk`` and ``findFileResources``. (`DM-33528 <https://jira.lsstcorp.org/browse/DM-33528>`_)
- * Modified the way that a schemeless absolute URI behaves such that we now always convert it to a ``file`` URI.
  * The ``root`` parameter can now use any ``ResourcePath`` scheme such that a relative URI can be treated as a URI relative to, for example, a S3 or WebDAV root. (`DM-38552 <https://jira.lsstcorp.org/browse/DM-38552>`_)
- The ``LSST_DISABLE_BUCKET_VALIDATION`` environment variable can now be set to disable validation of S3 bucket names, allowing Ceph multi-tenant colon-separated names to be used. (`DM-38742 <https://jira.lsstcorp.org/browse/DM-38742>`_)
- * Added support for ``as_local`` for Python package resource URIs.
  * Added explicit ``isdir()`` implementation for Python package resources. (`DM-39044 <https://jira.lsstcorp.org/browse/DM-39044>`_)


Bug Fixes
---------

- Fixed problem where a fragment associated with a schemeless URI was erroneously being quoted. (`DM-35695 <https://jira.lsstcorp.org/browse/DM-35695>`_)
- Fixed invalid endpoint error in the ``FileReadWriteTestCase`` test when the ``S3_ENDPOINT_URL`` environment variable is set to an invalid endpoint. (`DM-37439 <https://jira.lsstcorp.org/browse/DM-37439>`_)
- * Fixed EOF detection with S3 and HTTP resource handles when using repeated ``read()``.
  * Ensured that HTTP reads with resource handles using byte ranges correctly disable remote compression. (`DM-38589 <https://jira.lsstcorp.org/browse/DM-38589>`_)
- Reorganized ``mexists()`` implementation to allow S3 codepath to ensure that a client object was created before using multi-threading. (`DM-40762 <https://jira.lsstcorp.org/browse/DM-40762>`_)


Miscellaneous Changes of Minor Interest
---------------------------------------

- ``ResourcePathExpression`` can now be used in an `isinstance` call on Python 3.10 and newer. (`DM-38492 <https://jira.lsstcorp.org/browse/DM-38492>`_)


An API Removal or Deprecation
-----------------------------

- Dropped support for Python 3.8 and 3.9. (`DM-39791 <https://jira.lsstcorp.org/browse/DM-39791>`_)


Resources v25.0.0 2023-02-27
============================

Miscellaneous Changes of Minor Interest
---------------------------------------

- For file copies with ``transfer_from()`` an attempt is now made to make the copies atomic by using `os.rename` with a temporary intermediate.
  Moves now explicitly prefer `os.rename` and will fall back to an atomic copy before deletion if needed.
  This is useful if multiple processes are trying to copy to the same destination file. (`DM-36412 <https://jira.lsstcorp.org/browse/DM-36412>`_)
- Added ``allow_redirects=True`` to WebDAV HEAD requests since the default is ``False``.
  This is needed when interacting with WebDAV storage systems which have a frontend redirecting to backend servers. (`DM-36799 <https://jira.lsstcorp.org/browse/DM-36799>`_)


Resources v24.0.0 2022-08-26
============================

New Features
------------

- This package is now available on `PyPI as lsst-resources <https://pypi.org/project/lsst-resources/>`_.
- The ``lsst.daf.butler.ButlerURI`` code has been extracted from the ``daf_butler`` package and made into a standalone package. It is now known as `lsst.resources.ResourcePath` and distributed in the ``lsst-resources`` package.
- Add support for Google Cloud Storage access using the ``gs`` URI scheme. (`DM-27355 <https://jira.lsstcorp.org/browse/DM-27355>`_)
- Builds using ``setuptools`` now calculate versions from the Git repository, including the use of alpha releases for those associated with weekly tags. (`DM-32408 <https://jira.lsstcorp.org/browse/DM-32408>`_)
- Add an `open` method that returns a file-like buffer wrapped by a context manager. (`DM-32842 <https://jira.lsstcorp.org/browse/DM-32842>`_)
- Major cleanup of the WebDAV interface:

  * Improve client timeout and retries.
  * Improve management of persistent connections to avoid exhausting server
    resources when there are thousands of simultaneous clients.
  * Rename environment variables previously named ``LSST_BUTLER_*`` by:

      * ``LSST_HTTP_CACERT_BUNDLE``
      * ``LSST_HTTP_AUTH_BEARER_TOKEN``
      * ``LSST_HTTP_AUTH_CLIENT_CERT``
      * ``LSST_HTTP_AUTH_CLIENT_KEY``
      * ``LSST_HTTP_PUT_SEND_EXPECT_HEADER`` (`DM-33769 <https://jira.lsstcorp.org/browse/DM-33769>`_)


Miscellaneous Changes of Minor Interest
---------------------------------------

- Reorganize test code to enhance code reuse and allow new schemes to make use of existing tests. (`DM-33394 <https://jira.lsstcorp.org/browse/DM-33394>`_)
- Attempt to catch 429 Retry client error in S3 interface.
  This code is not caught by ``botocore`` itself since it is not part of the AWS standard but Google can generate it. (`DM-33597 <https://jira.lsstcorp.org/browse/DM-33597>`_)
- When walking the local file system symlinks to directories are now followed. (`DM-35446 <https://jira.lsstcorp.org/browse/DM-35446>`_)
