Resources v29.0.0 2025-03-25
============================

New Features
------------

- * Modified ``ResourcePath.join()`` to propagate fragments from the given path to the joined path.
    This now means that if the ``ResourcePath`` constructor finds a fragment that fragment will be used.
    Previously the fragment was dropped if a ``ResourcePath`` was given that had a fragment, or the fragment was treated as part of the filename if a plain string was given.
    This change means that filenames can no longer include ``#`` characters.
  * Added new ``ResourcePath.unquoted_fragment`` property to get the unquoted fragment. (`DM-46776 <https://rubinobs.atlassian.net/browse/DM-46776>`_)


Resources v28.0.0 2024-11-20
============================

New Features
------------

- Added a new method ``ResourcePath.to_fsspec()`` to return ``fsspec`` file system objects suitable for use in packages such as Astropy and Pyarrow. (`DM-44547 <https://rubinobs.atlassian.net/browse/DM-44547>`_)
- Added a ``.name`` (string) property to the handles returned by ``ResourcePath.open()``.
  Previously only the handle for local files had this property. (`DM-44762 <https://rubinobs.atlassian.net/browse/DM-44762>`_)
- Added support for the ``LSST_S3_USE_THREADS`` environment variable to control multithreading for S3 uploads, in addition to downloads. (`DM-46139 <https://rubinobs.atlassian.net/browse/DM-46139>`_)


Bug Fixes
---------

- Fixed the usage of ``SEEK_END`` in S3 and HTTP resource path handles. (`DM-44486 <https://rubinobs.atlassian.net/browse/DM-44486>`_)
- If there is no environment variable set explicitly declaring the directory to use for temporary files, ``HttpResourcePath`` now creates temporary files in the system default temporary directory instead of the current working directory. (`DM-44840 <https://rubinobs.atlassian.net/browse/DM-44840>`_)


Miscellaneous Changes of Minor Interest
---------------------------------------

- ``S3ResourceHandle`` now correctly converts ``NoSuchKey`` exception to ``FileNotFoundError`` when a read is attempted. (`DM-45732 <https://rubinobs.atlassian.net/browse/DM-45732>`_)


Resources 27.0.0 2024-05-28
===========================

This release requires Python 3.11 or newer.

New Features
------------

- Added methods to ResourcePath for generating presigned HTTP URLs: ``generate_presigned_get_url`` and ``generate_presigned_put_url``.  These are currently only implemented for S3. (`DM-41879 <https://rubinobs.atlassian.net/browse/DM-41879>`_)
- The ``forceDirectory`` flag now has three states.
  As before `True` indicates that it is known that the URI refers to a directory-like entity.
  Now `False` indicates that it is known that the URI refers to a file-like entity.
  `None` is the new default and that indicates that the caller does not know and that the status should be inferred either by checking the file system or looking for a trailing ``/``.
  It is now an error to create a ``ResourcePath`` which has a trailing ``/`` but with ``forceDirectory=False``. (`DM-42306 <https://rubinobs.atlassian.net/browse/DM-42306>`_)
- ``S3ResourcePath`` now supports using multiple S3 endpoints simultaneously.  This is configured using URIs in the form ``s3://profile@bucket/path`` and environment variables ``LSST_RESOURCES_S3_PROFILE_<profile>=https://<access key ID>:<secret key>@<s3 endpoint hostname>``. (`DM-42704 <https://rubinobs.atlassian.net/browse/DM-42704>`_)
- Allow threading of S3 downloads to be turned off by setting either the ``LSST_S3_USE_THREADS`` environment variable or the ``S3ResourcePath.use_threads`` class member. (`PREOPS-4765 <https://rubinobs.atlassian.net/browse/PREOPS-4765>`_)


Bug Fixes
---------

- When the process's filesystem umask set to a restrictive value like 0222, ``transfer_from``, ``write``, and ``mkdir`` no longer fail due to incorrect permissions on newly-created parent directories. (`DM-41112 <https://rubinobs.atlassian.net/browse/DM-41112>`_)
- Installing optional dependencies for ``s3`` and ``https`` will no longer pull in libraries only required for running unit tests (``moto`` and ``responses``). (`DM-41547 <https://rubinobs.atlassian.net/browse/DM-41547>`_)
- ``HttpResourcePath.exists()`` and ``HttpResourcePath.size()`` now work for S3 HTTP URLs pre-signed for GET. (`DM-42522 <https://rubinobs.atlassian.net/browse/DM-42522>`_)
- ``ResourePath.root_uri()`` now strips query parameters and fragments from the URL.  This fixes a memory leak where ``HttpResourcePath`` would create and cache a new HTTP session for each different set of query parameters. (`DM-43739 <https://rubinobs.atlassian.net/browse/DM-43739>`_)


Performance Enhancement
-----------------------

- * Schemeless URIs no longer check the file system on construction.
  * Both ``getExtension`` and ``relativeToPathRoot`` have been rewritten to no longer use `pathlib`.
  * It is now possible to declare that a URI is file-like on construction. Use ``forceDirectory=False``. (`DM-42306 <https://rubinobs.atlassian.net/browse/DM-42306>`_)


Miscellaneous Changes of Minor Interest
---------------------------------------

- * ``getExtension()`` now works for directories. (`DM-42306 <https://rubinobs.atlassian.net/browse/DM-42306>`_)


An API Removal or Deprecation
-----------------------------

- Deprecated ``clean_test_environment``, ``setAwsEnvCredentials``, and ``unsetAwsEnvCredentials`` from the ``s3utils`` submodule.  The new function ``clean_test_environment_for_s3`` replaces these. (`DM-41879 <https://rubinobs.atlassian.net/browse/DM-41879>`_)


Resources v26.0.0 2023-09-22
============================

This package now requires Python 3.10 and newer.

New Features
------------

- ``resource`` URI schemes now use `importlib.resources` (or ``importlib_resources``) rather than the deprecated ``pkg_resources``.
  Due to this change, ``resource`` URI schemes now also support ``walk`` and ``findFileResources``. (`DM-33528 <https://rubinobs.atlassian.net/browse/DM-33528>`_)
- * Modified the way that a schemeless absolute URI behaves such that we now always convert it to a ``file`` URI.
  * The ``root`` parameter can now use any ``ResourcePath`` scheme such that a relative URI can be treated as a URI relative to, for example, a S3 or WebDAV root. (`DM-38552 <https://rubinobs.atlassian.net/browse/DM-38552>`_)
- The ``LSST_DISABLE_BUCKET_VALIDATION`` environment variable can now be set to disable validation of S3 bucket names, allowing Ceph multi-tenant colon-separated names to be used. (`DM-38742 <https://rubinobs.atlassian.net/browse/DM-38742>`_)
- * Added support for ``as_local`` for Python package resource URIs.
  * Added explicit ``isdir()`` implementation for Python package resources. (`DM-39044 <https://rubinobs.atlassian.net/browse/DM-39044>`_)


Bug Fixes
---------

- Fixed problem where a fragment associated with a schemeless URI was erroneously being quoted. (`DM-35695 <https://rubinobs.atlassian.net/browse/DM-35695>`_)
- Fixed invalid endpoint error in the ``FileReadWriteTestCase`` test when the ``S3_ENDPOINT_URL`` environment variable is set to an invalid endpoint. (`DM-37439 <https://rubinobs.atlassian.net/browse/DM-37439>`_)
- * Fixed EOF detection with S3 and HTTP resource handles when using repeated ``read()``.
  * Ensured that HTTP reads with resource handles using byte ranges correctly disable remote compression. (`DM-38589 <https://rubinobs.atlassian.net/browse/DM-38589>`_)
- Reorganized ``mexists()`` implementation to allow S3 codepath to ensure that a client object was created before using multi-threading. (`DM-40762 <https://rubinobs.atlassian.net/browse/DM-40762>`_)


Miscellaneous Changes of Minor Interest
---------------------------------------

- ``ResourcePathExpression`` can now be used in an `isinstance` call on Python 3.10 and newer. (`DM-38492 <https://rubinobs.atlassian.net/browse/DM-38492>`_)


An API Removal or Deprecation
-----------------------------

- Dropped support for Python 3.8 and 3.9. (`DM-39791 <https://rubinobs.atlassian.net/browse/DM-39791>`_)


Resources v25.0.0 2023-02-27
============================

Miscellaneous Changes of Minor Interest
---------------------------------------

- For file copies with ``transfer_from()`` an attempt is now made to make the copies atomic by using `os.rename` with a temporary intermediate.
  Moves now explicitly prefer `os.rename` and will fall back to an atomic copy before deletion if needed.
  This is useful if multiple processes are trying to copy to the same destination file. (`DM-36412 <https://rubinobs.atlassian.net/browse/DM-36412>`_)
- Added ``allow_redirects=True`` to WebDAV HEAD requests since the default is ``False``.
  This is needed when interacting with WebDAV storage systems which have a frontend redirecting to backend servers. (`DM-36799 <https://rubinobs.atlassian.net/browse/DM-36799>`_)


Resources v24.0.0 2022-08-26
============================

New Features
------------

- This package is now available on `PyPI as lsst-resources <https://pypi.org/project/lsst-resources/>`_.
- The ``lsst.daf.butler.ButlerURI`` code has been extracted from the ``daf_butler`` package and made into a standalone package. It is now known as `lsst.resources.ResourcePath` and distributed in the ``lsst-resources`` package.
- Add support for Google Cloud Storage access using the ``gs`` URI scheme. (`DM-27355 <https://rubinobs.atlassian.net/browse/DM-27355>`_)
- Builds using ``setuptools`` now calculate versions from the Git repository, including the use of alpha releases for those associated with weekly tags. (`DM-32408 <https://rubinobs.atlassian.net/browse/DM-32408>`_)
- Add an `open` method that returns a file-like buffer wrapped by a context manager. (`DM-32842 <https://rubinobs.atlassian.net/browse/DM-32842>`_)
- Major cleanup of the WebDAV interface:

  * Improve client timeout and retries.
  * Improve management of persistent connections to avoid exhausting server
    resources when there are thousands of simultaneous clients.
  * Rename environment variables previously named ``LSST_BUTLER_*`` by:

      * ``LSST_HTTP_CACERT_BUNDLE``
      * ``LSST_HTTP_AUTH_BEARER_TOKEN``
      * ``LSST_HTTP_AUTH_CLIENT_CERT``
      * ``LSST_HTTP_AUTH_CLIENT_KEY``
      * ``LSST_HTTP_PUT_SEND_EXPECT_HEADER`` (`DM-33769 <https://rubinobs.atlassian.net/browse/DM-33769>`_)


Miscellaneous Changes of Minor Interest
---------------------------------------

- Reorganize test code to enhance code reuse and allow new schemes to make use of existing tests. (`DM-33394 <https://rubinobs.atlassian.net/browse/DM-33394>`_)
- Attempt to catch 429 Retry client error in S3 interface.
  This code is not caught by ``botocore`` itself since it is not part of the AWS standard but Google can generate it. (`DM-33597 <https://rubinobs.atlassian.net/browse/DM-33597>`_)
- When walking the local file system symlinks to directories are now followed. (`DM-35446 <https://rubinobs.atlassian.net/browse/DM-35446>`_)
