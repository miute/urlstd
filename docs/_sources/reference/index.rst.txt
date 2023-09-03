API Reference
=============


.. toctree::
   :maxdepth: 2
   :hidden:

   urlstd.error


.. currentmodule:: urlstd.error

Exceptions
----------

.. autosummary::

   HostParseError
   IDNAError
   IPv4AddressParseError
   IPv6AddressParseError
   URLParseError


.. currentmodule:: urlstd.parse

URL and URLSearchParams
-----------------------

.. autosummary::
   :toctree: generated
   :template: autosummary/class.rst

   URL
   URLSearchParams


Low-level APIs
--------------

Classes
^^^^^^^

.. autosummary::
   :toctree: generated

   BasicURLParser
   Host
   HostValidator
   IDNA
   Origin
   URLParserState
   URLRecord
   URLValidator
   ValidityState

Functions
^^^^^^^^^

.. autosummary::
   :toctree: generated

   parse_qsl
   parse_url
   string_percent_decode
   string_percent_encode
   urlencode
   urlparse
   utf8_decode
   utf8_encode
   utf8_percent_encode
