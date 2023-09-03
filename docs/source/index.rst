urlstd
======

.. image:: https://img.shields.io/pypi/v/urlstd.svg
   :alt: PyPI
   :target: https://pypi.org/project/urlstd/

.. image:: https://img.shields.io/pypi/pyversions/urlstd
   :alt: PyPI - Python Version
   :target: https://pypi.org/project/urlstd/

.. image:: https://img.shields.io/pypi/l/urlstd
   :alt: PyPI - License
   :target: https://pypi.org/project/urlstd/

.. image:: https://github.com/miute/urlstd/actions/workflows/main.yml/badge.svg
   :alt: CI
   :target: https://github.com/miute/urlstd/actions/workflows/main.yml

.. image:: https://codecov.io/gh/miute/urlstd/branch/main/graph/badge.svg?token=XJGM09H5TS
   :alt: codecov
   :target: https://codecov.io/gh/miute/urlstd

**urlstd** is a Python implementation of the WHATWG `URL Living Standard <https://url.spec.whatwg.org/>`_.

This library provides URL class, URLSearchParams class, and low-level APIs that comply with the URL specification.


Supported APIs
--------------

- `URL class <https://url.spec.whatwg.org/#url-class>`_: :class:`urlstd.parse.URL`

  - `canParse <https://url.spec.whatwg.org/#dom-url-canparse>`_: :meth:`~urlstd.parse.URL.can_parse`

  - `href <https://url.spec.whatwg.org/#dom-url-href>`_: :attr:`~urlstd.parse.URL.href`

  - `origin <https://url.spec.whatwg.org/#dom-url-origin>`_: :attr:`~urlstd.parse.URL.origin`

  - `protocol <https://url.spec.whatwg.org/#dom-url-protocol>`_: :attr:`~urlstd.parse.URL.protocol`

  - `username <https://url.spec.whatwg.org/#dom-url-username>`_: :attr:`~urlstd.parse.URL.username`

  - `password <https://url.spec.whatwg.org/#dom-url-password>`_: :attr:`~urlstd.parse.URL.password`

  - `host <https://url.spec.whatwg.org/#dom-url-host>`_: :attr:`~urlstd.parse.URL.host`

  - `hostname <https://url.spec.whatwg.org/#dom-url-hostname>`_: :attr:`~urlstd.parse.URL.hostname`

  - `port <https://url.spec.whatwg.org/#dom-url-port>`_: :attr:`~urlstd.parse.URL.port`

  - `pathname <https://url.spec.whatwg.org/#dom-url-pathname>`_: :attr:`~urlstd.parse.URL.pathname`

  - `search <https://url.spec.whatwg.org/#dom-url-search>`_: :attr:`~urlstd.parse.URL.search`

  - `searchParams <https://url.spec.whatwg.org/#dom-url-searchparams>`_: :attr:`~urlstd.parse.URL.search_params`

  - `hash <https://url.spec.whatwg.org/#dom-url-hash>`_: :attr:`~urlstd.parse.URL.hash`

- `URLSearchParams class <https://url.spec.whatwg.org/#interface-urlsearchparams>`_: :class:`urlstd.parse.URLSearchParams`

  - `append <https://url.spec.whatwg.org/#dom-urlsearchparams-append>`_: :meth:`~urlstd.parse.URLSearchParams.append`

  - `delete <https://url.spec.whatwg.org/#dom-urlsearchparams-delete>`_: :meth:`~urlstd.parse.URLSearchParams.delete`

  - `get <https://url.spec.whatwg.org/#dom-urlsearchparams-get>`_: :meth:`~urlstd.parse.URLSearchParams.get`

  - `getAll <https://url.spec.whatwg.org/#dom-urlsearchparams-getall>`_: :meth:`~urlstd.parse.URLSearchParams.get_all`

  - `has <https://url.spec.whatwg.org/#dom-urlsearchparams-has>`_: :meth:`~urlstd.parse.URLSearchParams.has`

  - `set <https://url.spec.whatwg.org/#dom-urlsearchparams-set>`_: :meth:`~urlstd.parse.URLSearchParams.set`

  - `sort <https://url.spec.whatwg.org/#dom-urlsearchparams-sort>`_: :meth:`~urlstd.parse.URLSearchParams.sort`

- Low-level APIs

  - `URL parser <https://url.spec.whatwg.org/#concept-url-parser>`_: :func:`urlstd.parse.parse_url`

  - `basic URL parser <https://url.spec.whatwg.org/#concept-basic-url-parser>`_: :meth:`urlstd.parse.BasicURLParser.parse`

  - `URL record <https://url.spec.whatwg.org/#concept-url>`_: :class:`urlstd.parse.URLRecord`

    - `scheme <https://url.spec.whatwg.org/#concept-url-scheme>`_: :attr:`~urlstd.parse.URLRecord.scheme`

    - `username <https://url.spec.whatwg.org/#concept-url-username>`_: :attr:`~urlstd.parse.URLRecord.username`

    - `password <https://url.spec.whatwg.org/#concept-url-password>`_: :attr:`~urlstd.parse.URLRecord.password`

    - `host <https://url.spec.whatwg.org/#concept-url-host>`_: :attr:`~urlstd.parse.URLRecord.host`

    - `port <https://url.spec.whatwg.org/#concept-url-port>`_: :attr:`~urlstd.parse.URLRecord.port`

    - `path <https://url.spec.whatwg.org/#concept-url-path>`_: :attr:`~urlstd.parse.URLRecord.path`

    - `query <https://url.spec.whatwg.org/#concept-url-query>`_: :attr:`~urlstd.parse.URLRecord.query`

    - `fragment <https://url.spec.whatwg.org/#concept-url-fragment>`_: :attr:`~urlstd.parse.URLRecord.fragment`

    - `origin <https://url.spec.whatwg.org/#concept-url-origin>`_: :attr:`~urlstd.parse.URLRecord.origin`

    - `is special <https://url.spec.whatwg.org/#is-special>`_: :meth:`~urlstd.parse.URLRecord.is_special`

    - `is not special <https://url.spec.whatwg.org/#is-not-special>`_: :meth:`~urlstd.parse.URLRecord.is_not_special`

    - `includes credentials <https://url.spec.whatwg.org/#include-credentials>`_: :meth:`~urlstd.parse.URLRecord.includes_credentials`

    - `has an opaque path <https://url.spec.whatwg.org/#url-opaque-path>`_: :meth:`~urlstd.parse.URLRecord.has_opaque_path`

    - `cannot have a username/password/port <https://url.spec.whatwg.org/#cannot-have-a-username-password-port>`_: :meth:`~urlstd.parse.URLRecord.cannot_have_username_password_port`

    - `URL serializer <https://url.spec.whatwg.org/#concept-url-serializer>`_: :meth:`~urlstd.parse.URLRecord.serialize_url`

    - `host serializer <https://url.spec.whatwg.org/#concept-host-serializer>`_: :meth:`~urlstd.parse.URLRecord.serialize_host`

    - `URL path serializer <https://url.spec.whatwg.org/#url-path-serializer>`_: :meth:`~urlstd.parse.URLRecord.serialize_path`

  - `Hosts (domains and IP addresses) <https://url.spec.whatwg.org/#hosts-(domains-and-ip-addresses)>`_

    - `IDNA <https://url.spec.whatwg.org/#idna>`_

      - `domain to ASCII <https://url.spec.whatwg.org/#concept-domain-to-ascii>`_: :meth:`urlstd.parse.IDNA.domain_to_ascii`

      - `domain to Unicode <https://url.spec.whatwg.org/#concept-domain-to-unicode>`_: :meth:`urlstd.parse.IDNA.domain_to_unicode`

    - `host parser <https://url.spec.whatwg.org/#concept-host-parser>`_: :meth:`urlstd.parse.Host.parse`

    - `host serializer <https://url.spec.whatwg.org/#concept-host-serializer>`_: :meth:`urlstd.parse.Host.serialize`

  - `percent-decode a string <https://url.spec.whatwg.org/#string-percent-decode>`_: :func:`urlstd.parse.string_percent_decode`

  - `percent-encode after encoding <https://url.spec.whatwg.org/#string-percent-encode-after-encoding>`_: :func:`urlstd.parse.string_percent_encode`

  - `application/x-www-form-urlencoded parser <https://url.spec.whatwg.org/#concept-urlencoded-parser>`_: :func:`urlstd.parse.parse_qsl`

  - `application/x-www-form-urlencoded serializer <https://url.spec.whatwg.org/#concept-urlencoded-serializer>`_: :func:`urlstd.parse.urlencode`

  - Validation

    - Hosts (domains and IP addresses): :class:`urlstd.parse.HostValidator`

      - `valid host string <https://url.spec.whatwg.org/#valid-host-string>`_: :meth:`~urlstd.parse.HostValidator.is_valid`

      - `valid domain string <https://url.spec.whatwg.org/#valid-domain-string>`_: :meth:`~urlstd.parse.HostValidator.is_valid_domain`

      - `valid IPv4-address string <https://url.spec.whatwg.org/#valid-ipv4-address-string>`_: :meth:`~urlstd.parse.HostValidator.is_valid_ipv4_address`

      - `valid IPv6-address string <https://url.spec.whatwg.org/#valid-ipv6-address-string>`_: :meth:`~urlstd.parse.HostValidator.is_valid_ipv6_address`

    - URL: :class:`urlstd.parse.URLValidator`

      - `valid URL string <https://url.spec.whatwg.org/#valid-url-string>`_: :meth:`~urlstd.parse.URLValidator.is_valid`

      - `valid URL-scheme string <https://url.spec.whatwg.org/#url-scheme-string>`_: :meth:`~urlstd.parse.URLValidator.is_valid_url_scheme`

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   user-guide
   reference/index


Indices and Tables
------------------

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
