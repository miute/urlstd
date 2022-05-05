# urlstd

[![PyPI](https://img.shields.io/pypi/v/urlstd)](https://pypi.org/project/urlstd/)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/urlstd)](https://pypi.org/project/urlstd/)
[![PyPI - License](https://img.shields.io/pypi/l/urlstd)](https://pypi.org/project/urlstd/)
[![CI](https://github.com/miute/urlstd/actions/workflows/main.yml/badge.svg)](https://github.com/miute/urlstd/actions/workflows/main.yml)
[![codecov](https://codecov.io/gh/miute/urlstd/branch/main/graph/badge.svg?token=XJGM09H5TS)](https://codecov.io/gh/miute/urlstd)

`urlstd` is a Python implementation of the WHATWG [URL Standard](https://url.spec.whatwg.org/).

This library provides `URL` class, `URLSearchParams` class, and low-level APIs that comply with the URL specification.

*Note: The latest release of urlstd is implemented based on the URL specification commit [f787850](https://github.com/whatwg/url/commit/f787850695969d51caaa5c290f2c2e050e083638).*

## Supported APIs

- [URL class](https://url.spec.whatwg.org/#url-class)
  - class urlstd.parse.`URL(url: str, base: Optional[str] = None)`
    - [href](https://url.spec.whatwg.org/#dom-url-href): `readonly property href: str`
    - [origin](https://url.spec.whatwg.org/#dom-url-origin): `readonly property origin: str`
    - [protocol](https://url.spec.whatwg.org/#dom-url-protocol): `property protocol: str`
    - [username](https://url.spec.whatwg.org/#dom-url-username): `property username: str`
    - [password](https://url.spec.whatwg.org/#dom-url-password): `property password: str`
    - [host](https://url.spec.whatwg.org/#dom-url-host): `property host: str`
    - [hostname](https://url.spec.whatwg.org/#dom-url-hostname): `property hostname: str`
    - [port](https://url.spec.whatwg.org/#dom-url-port): `property port: str`
    - [pathname](https://url.spec.whatwg.org/#dom-url-pathname): `property pathname: str`
    - [search](https://url.spec.whatwg.org/#dom-url-search): `property search: str`
    - [searchParams](https://url.spec.whatwg.org/#dom-url-searchparams): `readonly property search_params: URLSearchParams`
    - [hash](https://url.spec.whatwg.org/#dom-url-hash): `property hash: str`

- [URLSearchParams class](https://url.spec.whatwg.org/#interface-urlsearchparams)
  - class urlstd.parse.`URLSearchParams(init: Optional[Union[str, Sequence[Sequence[Union[str, int, float]]], Dict[str, Union[str, int, float]], URLRecord, URLSearchParams]] = None)`
    - [append](https://url.spec.whatwg.org/#dom-urlsearchparams-append): `append(name: str, value: Union[str, int, float]) -> None`
    - [delete](https://url.spec.whatwg.org/#dom-urlsearchparams-delete): `delete(name: str) -> None`
    - [get](https://url.spec.whatwg.org/#dom-urlsearchparams-get): `get(name: str) -> Optional[str]`
    - [getAll](https://url.spec.whatwg.org/#dom-urlsearchparams-getall): `get_all(name: str) -> Tuple[str, ...]`
    - [has](https://url.spec.whatwg.org/#dom-urlsearchparams-has): `has(name: str) -> bool`
    - [set](https://url.spec.whatwg.org/#dom-urlsearchparams-set): `set(name: str, value: Union[str, int, float]) -> None`
    - [sort](https://url.spec.whatwg.org/#dom-urlsearchparams-sort): `sort() -> None`

- Low-level APIs

  - [URL parser](https://url.spec.whatwg.org/#concept-url-parser)
    - urlstd.parse.`parse_url(urlstring: str, base: str = None, encoding: str = "utf-8") -> URLRecord`

  - [basic URL parser](https://url.spec.whatwg.org/#concept-basic-url-parser)
    - class urlstd.parse.`BasicURLParser`
      - classmethod `parse(urlstring: str, base: Optional[URLRecord] = None, encoding: str = "utf-8", url: Optional[URLRecord] = None, state_override: Optional[URLParserState] = None) -> URLRecord`

  - [URL record](https://url.spec.whatwg.org/#concept-url)
    - class urlstd.parse.`URLRecord`
      - [scheme](https://url.spec.whatwg.org/#concept-url-scheme): `property scheme: str = ""`
      - [username](https://url.spec.whatwg.org/#concept-url-username): `property username: str = ""`
      - [password](https://url.spec.whatwg.org/#concept-url-password): `property password: str = ""`
      - [host](https://url.spec.whatwg.org/#concept-url-host): `property host: Optional[Union[str, int, Tuple[int, ...]]] = None`
      - [port](https://url.spec.whatwg.org/#concept-url-port): `property port: Optional[int] = None`
      - [path](https://url.spec.whatwg.org/#concept-url-path): `property path: Union[List[str], str] = []`
      - [query](https://url.spec.whatwg.org/#concept-url-query): `property query: Optional[str] = None`
      - [fragment](https://url.spec.whatwg.org/#concept-url-fragment): `property fragment: Optional[str] = None`
      - [origin](https://url.spec.whatwg.org/#concept-url-origin): `readonly property origin: Optional[Origin]`
      - [is special](https://url.spec.whatwg.org/#is-special): `is_special() -> bool`
      - [is not special](https://url.spec.whatwg.org/#is-not-special): `is_not_special() -> bool`
      - [includes credentials](https://url.spec.whatwg.org/#include-credentials): `includes_credentials() -> bool`
      - [has an opaque path](https://url.spec.whatwg.org/#url-opaque-path): `has_opaque_path() -> bool`
      - [cannot have a username/password/port](https://url.spec.whatwg.org/#cannot-have-a-username-password-port): `cannot_have_username_password_port() -> bool`
      - [URL serializer](https://url.spec.whatwg.org/#concept-url-serializer): `serialize_url(exclude_fragment: bool = False) -> str`
      - [host serializer](https://url.spec.whatwg.org/#concept-host-serializer): `serialize_host() -> str`
      - [URL path serializer](https://url.spec.whatwg.org/#url-path-serializer): `serialize_path() -> str`

  - [domain to ASCII](https://url.spec.whatwg.org/#concept-domain-to-ascii)
    - urlstd.parse.IDNA.`domain_to_ascii(domain: str, be_strict: bool = False) -> str`

  - [host parser](https://url.spec.whatwg.org/#concept-host-parser)
    - urlstd.parse.Host.`parse(host: str, is_not_special: bool = False) -> Union[str, int, Tuple[int, ...]]`

  - [host serializer](https://url.spec.whatwg.org/#concept-host-serializer)
    - urlstd.parse.Host.`serialize(host: Union[str, int, Sequence[int]]) -> str`

  - [percent-decode a string](https://url.spec.whatwg.org/#string-percent-decode)
    - urlstd.parse.`string_percent_decode(s: str) -> bytes`

  - [percent-encode after encoding](https://url.spec.whatwg.org/#string-percent-encode-after-encoding)
    - urlstd.parse.`string_percent_encode(s: str, safe: str, encoding: str = "utf-8", space_as_plus: bool = False) -> str`

  - [application/x-www-form-urlencoded parser](https://url.spec.whatwg.org/#concept-urlencoded-parser)
    - urlstd.parse.`parse_qsl(query: bytes) -> List[Tuple[str, str]]`

  - [application/x-www-form-urlencoded serializer](https://url.spec.whatwg.org/#concept-urlencoded-serializer)
    - urlstd.parse.`urlencode(query: Sequence[Tuple[str, str]], encoding: str = "utf-8") -> str`

- Compatibility with standard library `urllib`
  - urlstd.parse.`urlparse(urlstring: str, base: str = None, encoding: str = "utf-8", allow_fragments: bool = True) -> urllib.parse.ParseResult`

    `urlstd.parse.urlparse()` ia an alternative to `urllib.parse.urlparse()`.
    Parses a string representation of a URL using the basic URL parser, and returns `urllib.parse.ParseResult`.

## Basic Usage

To parse a string into a `URL` with using a base URL:

```python
from urlstd.parse import URL
url = URL('?ﬃ&🌈', 'http://example.org')
url  # → URL(href='http://example.org/?%EF%AC%83&%F0%9F%8C%88', origin='http://example.org', protocol='http:', username='', password='', host='example.org', hostname='example.org', port='', pathname='/', search='?%EF%AC%83&%F0%9F%8C%88', hash='')
url.search  # → '?%EF%AC%83&%F0%9F%8C%88'
params = url.search_params
params  # → URLSearchParams([('ﬃ', ''), ('🌈', '')])
params.sort()
params  # → URLSearchParams([('🌈', ''), ('ﬃ', '')])
url.search  # → '?%F0%9F%8C%88=&%EF%AC%83='
str(url)  # → 'http://example.org/?%F0%9F%8C%88=&%EF%AC%83='
```

To parse a string into a `urllib.parse.ParseResult` with using a base URL:

```python
import html
from urllib.parse import unquote
from urlstd.parse import urlparse
pr = urlparse('?aÿb', 'http://example.org/foo/', encoding='utf-8')
pr  # → ParseResult(scheme='http', netloc='example.org', path='/foo/', params='', query='a%C3%BFb', fragment='')
unquote(pr.query)  # → 'aÿb'
pr = urlparse('?aÿb', 'http://example.org/foo/', encoding='windows-1251')
pr  # → ParseResult(scheme='http', netloc='example.org', path='/foo/', params='', query='a%26%23255%3Bb', fragment='')
unquote(pr.query, encoding='windows-1251')  # → 'a&#255;b'
html.unescape('a&#255;b')  # → 'aÿb'
pr = urlparse('?aÿb', 'http://example.org/foo/', encoding='windows-1252')
pr  # → ParseResult(scheme='http', netloc='example.org', path='/foo/', params='', query='a%FFb', fragment='')
unquote(pr.query, encoding='windows-1252')  # → 'aÿb'
```

## Logging

`urlstd` uses standard library `logging` for [validation error](https://url.spec.whatwg.org/#validation-error).
Change the logger log level of urlstd if needed:

```python
logging.getLogger('urlstd').setLevel(logging.ERROR)
```

## Dependencies

- [icupy](https://pypi.org/project/icupy/) >= 0.11.0 (pre-built packages are [available](https://github.com/miute/icupy/releases))
  - icupy requirements:
    - [ICU4C](https://github.com/unicode-org/icu/releases) ([ICU - International Components for Unicode](https://icu.unicode.org/)) - latest version recommended
    - C++17 compatible compiler (see [supported compilers](https://github.com/pybind/pybind11#supported-compilers))
    - [CMake](https://cmake.org/) >= 3.7

## Installation

1. Configuring environment variables for icupy (ICU):
    - Windows:
      - Set the `ICU_ROOT` environment variable to the root of the ICU installation (default is `C:\icu`).
        For example, if the ICU is located in `C:\icu4c`:

        ```bat
        set ICU_ROOT=C:\icu4c
        ```

        or in PowerShell:

        ```bat
        $env:ICU_ROOT = "C:\icu4c"
        ```

      - To verify settings using *icuinfo (64 bit)*:

        ```bat
        %ICU_ROOT%\bin64\icuinfo
        ```

        or in PowerShell:

        ```bat
        & $env:ICU_ROOT\bin64\icuinfo
        ```

    - Linux/POSIX:
      - If the ICU is located in a non-regular place, set the `PKG_CONFIG_PATH` and `LD_LIBRARY_PATH` environment variables.
        For example, if the ICU is located in `/usr/local`:

        ```bash
        export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH
        export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
        ```

      - To verify settings using *pkg-config*:

        ```bash
        $ pkg-config --cflags --libs icu-uc
        -I/usr/local/include -L/usr/local/lib -licuuc -licudata
        ```

2. Installing from PyPI:

    ```bash
    pip install urlstd
    ```

## Running Tests

Install dependencies:

```bash
pip install tox
```

To run tests and generate a report:

```bash
git clone https://github.com/miute/urlstd.git
cd urlstd
tox -e wpt
```

See result: [tests/wpt/report.html](https://htmlpreview.github.io/?https://github.com/miute/urlstd/blob/main/tests/wpt/report.html)

## License

[MIT License](https://github.com/miute/urlstd/blob/main/LICENSE).
