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
