User Guide
==========

Dependencies
------------

- `icupy <https://pypi.org/project/icupy/>`_ >=0.11.0

  .. note::
    icupy requirements:
      - `ICU <https://icu.unicode.org>`_ - International Components for Unicode
        (`ICU4C <https://github.com/unicode-org/icu/releases>`_)
      - C++17 compatible compiler
      - `CMake <https://cmake.org>`_


Installation
------------

1. Configuring environment variables for icupy (ICU):

   - Windows:

     - Set the **ICU_ROOT** environment variable to the root of the ICU installation (default is "C:\\icu").
       For example, if the ICU is located in "C:\\icu4c":

       .. tab:: Command Prompt

         .. code-block:: bat

           set ICU_ROOT=C:\icu4c

       .. tab:: PowerShell

         .. code-block:: powershell

           $env:ICU_ROOT = "C:\icu4c"

       To verify settings using *icuinfo*:

       .. tab:: Command Prompt (64 bit)

         .. code-block:: bat

           %ICU_ROOT%\bin64\icuinfo

       .. tab:: PowerShell (64 bit)

         .. code-block:: powershell

           & $env:ICU_ROOT\bin64\icuinfo

   - Linux/POSIX:

     - If the ICU is located in a non-regular place, set the **PKG_CONFIG_PATH** and **LD_LIBRARY_PATH** environment variables.
       For example, if the ICU is located in "/usr/local":

       .. code-block:: bash

         export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH
         export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

2. Installing from PyPI:

   .. code-block:: bash

     pip install urlstd


Basic Usage
-----------

To parse a string into a :class:`~urlstd.parse.URL` with using a base URL:

.. code-block:: python

    >>> from urlstd.parse import URL
    >>> url = URL('?ﬃ&🌈', 'http://example.org')
    >>> url
    URL(href='http://example.org/?%EF%AC%83&%F0%9F%8C%88', origin='http://example.org', protocol='http:', username='', password='', host='example.org', hostname='example.org', port='', pathname='/', search='?%EF%AC%83&%F0%9F%8C%88', hash='')
    >>> url.search
    '?%EF%AC%83&%F0%9F%8C%88'
    >>> params = url.search_params
    >>> params
    URLSearchParams([('ﬃ', ''), ('🌈', '')])
    >>> params.sort()
    >>> params
    URLSearchParams([('🌈', ''), ('ﬃ', '')])
    >>> url.search
    '?%F0%9F%8C%88=&%EF%AC%83='
    >>> str(url)
    'http://example.org/?%F0%9F%8C%88=&%EF%AC%83='

:func:`urlstd.parse.urlparse` is an alternative to *urllib.parse.urlparse()*.
To parse a string into a *urllib.parse.ParseResult* with using a base URL:

.. code-block:: python

    >>> import html
    >>> from urllib.parse import unquote
    >>> from urlstd.parse import urlparse
    >>> pr = urlparse('?aÿb', 'http://example.org/foo/', encoding='utf-8')
    >>> pr
    ParseResult(scheme='http', netloc='example.org', path='/foo/', params='', query='a%C3%BFb', fragment='')
    >>> unquote(pr.query)
    'aÿb'
    >>> pr = urlparse('?aÿb', 'http://example.org/foo/', encoding='windows-1251')
    >>> pr
    ParseResult(scheme='http', netloc='example.org', path='/foo/', params='', query='a%26%23255%3Bb', fragment='')
    >>> unquote(pr.query, encoding='windows-1251')
    'a&#255;b'
    >>> html.unescape('a&#255;b')
    'aÿb'
    >>> pr = urlparse('?aÿb', 'http://example.org/foo/', encoding='windows-1252')
    >>> pr
    ParseResult(scheme='http', netloc='example.org', path='/foo/', params='', query='a%FFb', fragment='')
    >>> unquote(pr.query, encoding='windows-1252')
    'aÿb'


Logging
-------

**urlstd** uses standard library *logging* for `validation error <https://url.spec.whatwg.org/#validation-error>`_.
Change the logger log level of **urlstd** if needed:

.. code-block:: python

    logging.getLogger('urlstd').setLevel(logging.ERROR)
