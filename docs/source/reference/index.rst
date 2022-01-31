API Reference
=============


Modules
-------

.. toctree::

   urlstd.parse
   urlstd.error


.. currentmodule:: urlstd.parse

URL and URLSearchParams
-----------------------

.. autosummary::

   URL
   URLSearchParams


Low-level APIs
--------------

Classes
^^^^^^^

.. autosummary::

   BasicURLParser
   Host
   IDNA
   Origin
   URLParserState
   URLRecord

Functions
^^^^^^^^^

.. autosummary::

   parse_qsl
   parse_url
   string_percent_decode
   string_percent_encode
   urlencode
   urlparse
   utf8_decode
   utf8_encode
   utf8_percent_encode


.. currentmodule:: urlstd.error

Exceptions
^^^^^^^^^^

.. autosummary::

   HostParseError
   IDNAError
   IPv4AddressParseError
   IPv6AddressParseError
   URLParseError
