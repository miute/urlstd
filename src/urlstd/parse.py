"""
Python implementation of the WHATWG URL Standard
"""

import codecs
import collections.abc
import copy
import enum
import re
import string
from dataclasses import dataclass, field
from ipaddress import IPv6Address
from logging import Logger, getLogger
from typing import (
    Any,
    Dict,
    Iterable,
    Iterator,
    List,
    NamedTuple,
    Optional,
    Sequence,
    Tuple,
    Union,
    overload,
)
from urllib.parse import ParseResult, quote, quote_plus
from urllib.parse import unquote_to_bytes as percent_decode

import icupy.icu as icu

from .error import (
    HostParseError,
    IDNAError,
    IPv4AddressParseError,
    IPv6AddressParseError,
    URLParseError,
)

__all__ = [
    "BasicURLParser",
    "Host",
    "IDNA",
    "Origin",
    "URL",
    "URLParserState",
    "URLRecord",
    "URLSearchParams",
    "parse_qsl",
    "parse_url",
    "string_percent_decode",
    "string_percent_encode",
    "urlencode",
    "urlparse",
    "utf8_decode",
    "utf8_encode",
    "utf8_percent_encode",
]

ASCII_TAB_OR_NEWLINE_RE = re.compile(r"[\t\x0a\x0d]")

LEADING_AND_TRAILING_C0_CONTROL_AND_SPACE_RE = re.compile(
    r"^[\x00-\x1f\x20]+|[\x00-\x1f\x20]+$"
)

PERCENT_RE = re.compile(r"%[^%]*")

ASCII_ALPHA = string.ascii_letters

ASCII_ALPHANUMERIC = string.ascii_letters + string.digits

ASCII_DIGITS = string.digits

ASCII_HEX_DIGITS = string.hexdigits

FORBIDDEN_HOST_CODE_POINT = "\x00\t\x0a\x0d #%/:<>?@[\\]^|"

FORBIDDEN_HOST_CODE_POINT_EXCLUDING_PERCENT = "\x00\t\x0a\x0d #/:<>?@[\\]^|"

# SURROGATE = set(range(0xd800, 0xe000))
# NONCHARACTER = (set(range(0xfdd0, 0xfdf0)) |
#                 {0xfffe, 0xffff, 0x1fffe, 0x1ffff, 0x2fffe,
#                  0x2ffff, 0x3fffe, 0x3ffff, 0x4fffe, 0x4ffff,
#                  0x5fffe, 0x5ffff, 0x6fffe, 0x6ffff, 0x7fffe,
#                  0x7ffff, 0x8fffe, 0x8ffff, 0x9fffe, 0x9ffff,
#                  0xafffe, 0xaffff, 0xbfffe, 0xbffff, 0xcfffe,
#                  0xcffff, 0xdfffe, 0xdffff, 0xefffe, 0xeffff,
#                  0xffffe, 0xfffff, 0x10fffe, 0x10ffff})
# URL_CODE_POINTS = ''.join(
#     sorted(
#         set(ASCII_ALPHANUMERIC + "!$&'()*+,-./:;=?@_~") |
#         {chr(x) for x in set(range(0xa0, 0x10fffe)) - SURROGATE - NONCHARACTER}
#     )
# )

SAFE_C0_CONTROL_PERCENT_ENCODE_SET = "".join(
    [chr(x) for x in range(0x20, 0x7F)]
)

SAFE_FRAGMENT_PERCENT_ENCODE_SET = "".join(
    sorted(set(SAFE_C0_CONTROL_PERCENT_ENCODE_SET) - set(' "<>`'))
)

SAFE_QUERY_PERCENT_ENCODE_SET = "".join(
    sorted(set(SAFE_C0_CONTROL_PERCENT_ENCODE_SET) - set(' "#<>'))
)

SAFE_SPECIAL_QUERY_PERCENT_ENCODE_SET = "".join(
    sorted(set(SAFE_QUERY_PERCENT_ENCODE_SET) - set("'"))
)

SAFE_PATH_PERCENT_ENCODE_SET = "".join(
    sorted(set(SAFE_QUERY_PERCENT_ENCODE_SET) - set("?`{}"))
)

SAFE_USERINFO_PERCENT_ENCODE_SET = "".join(
    sorted(set(SAFE_PATH_PERCENT_ENCODE_SET) - set("/:;=@[\\]^|"))
)

SAFE_COMPONENT_PERCENT_ENCODE_SET = "".join(
    sorted(set(SAFE_USERINFO_PERCENT_ENCODE_SET) - set("$%&+,"))
)

SAFE_URLENCODED_PERCENT_ENCODE_SET = "".join(
    sorted(set(SAFE_COMPONENT_PERCENT_ENCODE_SET) - set("!'()~"))
)

SINGLE_DOT_PATH_SEGMENTS = frozenset([".", "%2e", "%2E"])

DOUBLE_DOT_PATH_SEGMENTS = frozenset(
    [
        "..",
        ".%2e",
        ".%2E",
        "%2e.",
        "%2E.",
        "%2e%2e",
        "%2e%2E",
        "%2E%2e",
        "%2E%2E",
    ]
)

SPECIAL_SCHEMES = {
    "ftp": 21,
    "file": None,
    "http": 80,
    "https": 443,
    "ws": 80,
    "wss": 443,
}

UTF8_CODECS = frozenset(["utf_8", "u8", "utf", "utf8", "cp65001"])

UTF16BE_CODECS = frozenset(["utf_16_be", "utf-16be", "utf-16-be"])

UTF16LE_CODECS = frozenset(["utf_16_le", "utf-16le", "utf-16-le"])


def cpstream(s: str) -> Iterable[str]:
    for c in s:
        yield c
    else:
        yield ""  # EOF


def get_logger(context: Any) -> Logger:
    name = None
    if isinstance(context, str):
        name = context
    elif hasattr(context, "__module__") and hasattr(context, "__name__"):
        name = f"{context.__module__}.{context.__name__}"
    elif hasattr(context, "__module__") and hasattr(context, "__class__"):
        name = f"{context.__module__}.{context.__class__.__name__}"
    return getLogger(name)


def iscp(c: str, target: str) -> bool:
    return len(c) != 0 and c in target


def iseof(c: str) -> bool:
    return len(c) == 0


def is_normalized_windows_drive_letter(text: str) -> bool:
    return is_windows_drive_letter(text) and text[1] == ":"


def is_windows_drive_letter(text: str) -> bool:
    return len(text) == 2 and text[0] in ASCII_ALPHA and text[1] in ":|"


def parse_qsl(query: bytes) -> List[Tuple[str, str]]:
    r"""An alternative to :func:`urllib.parse.parse_qsl`.

    Parses a byte sequence in the form application/x-www-form-urlencoded,
    and returns a list of utf-8 decoded name-value pairs.

    Invalid surrogates will be replaced with U+FFFD.

    Args:
        query: A byte sequence to parse.

    Returns:
        A list of utf-8 decoded name-value pairs.

    Examples:
        >>> parse_qsl(b'a=a&a=b&a=c')
        [('a', 'a'), ('a', 'b'), ('a', 'c')]

        >>> parse_qsl(b'%61+%4d%4D=')
        [('a MM', '')]

        >>> parse_qsl(b'%FE%FF')
        [('\ufffd\ufffd', '')]
    """
    sequences = query.split(b"&")
    output = []
    for sequence in sequences:
        if len(sequence) == 0:
            continue
        name_value = (sequence.split(b"=", maxsplit=1) + [b""])[:2]
        b = name_value[0].replace(b"+", b" ")
        b = percent_decode(b)
        name = utf8_decode(b)
        b = name_value[1].replace(b"+", b" ")
        b = percent_decode(b)
        value = utf8_decode(b)
        output.append((name, value))
    return output


def starts_with_windows_drive_letter(text: str) -> bool:
    return (
        len(text) >= 2
        and is_windows_drive_letter(text[:2])
        and (len(text) == 2 or text[2] in "/\\?#")
    )


def string_percent_decode(s: str) -> bytes:
    r"""Returns a percent-decoded byte sequence after encoding with utf-8.

    Invalid surrogates will be replaced with U+FFFD.

    Args:
        s: A string to percent-decode.

    Returns:
        A percent-decoded byte sequence after encoding with utf-8.

    Examples:
        >>> string_percent_decode('%f0%9f%8c%88').decode()
        '🌈'

        >>> string_percent_decode('\U0001f308').decode()
        '🌈'

        >>> string_percent_decode('\ud83c\udf08').decode()
        '🌈'

        >>> string_percent_decode('\udf08\ud83c').decode()
        '\ufffd\ufffd'
    """
    b = utf8_encode(s)
    return percent_decode(b)


def string_percent_encode(
    s: str, safe: str, encoding: str = "utf-8", space_as_plus: bool = False
) -> str:
    r"""Returns a percent-encoded string after encoding with *encoding*.

    Invalid surrogates will be replaced with U+FFFD.
    Also, if the encoding fails, it will be replaced with the appropriate XML
    character reference.

    Args:
        s: A string to percent-encode.
        safe: ASCII characters that should not be percent-encoded.
        encoding: The encoding to encode *s*.
        space_as_plus: If *True*, replace 0x20 (space) with U+002B (plus sign).

    Returns:
        A percent-encoded string after encoding with *encoding*.

    Examples:
        >>> string_percent_encode('/El Niño/', '/')
        '/El%20Ni%C3%B1o/'

        >>> string_percent_encode('\U0001f308', '')
        '%F0%9F%8C%88'

        >>> string_percent_encode('\ud83c\udf08', '')
        '%F0%9F%8C%88'

        >>> string_percent_encode('\ud83c', '')
        '%EF%BF%BD'  # → '\ufffd'

        >>> string_percent_encode('\U0001f308', '', encoding='windows-1252')
        '%26%23127752%3B'  # → '&#127752;'
    """
    s = s.encode("utf-16", "surrogatepass").decode("utf-16", "replace")
    quote_via = quote_plus if space_as_plus else quote
    try:
        return quote_via(s, safe=safe, encoding=encoding, errors="strict")
    except UnicodeEncodeError:
        pass

    output = ""
    for b in codecs.iterencode(s, encoding, errors="xmlcharrefreplace"):
        if b.startswith(b"&#"):
            output += quote_via(b)  # "%26%23" ASCII-digits "%3B"
        else:
            output += quote_via(b, safe=safe)
    return output


def urlencode(
    query: Sequence[Tuple[str, str]], encoding: str = "utf-8"
) -> str:
    r"""An alternative to :func:`urllib.parse.urlencode`.

    Converts a sequence of tuples of name-value pairs into a percent-encoded
    ASCII text string in the form application/x-www-form-urlencoded.

    Invalid surrogates will be replaced with U+FFFD.
    Also, if the encoding fails, it will be replaced with the appropriate XML
    character reference.

    Args:
        query: A sequence of tuples of name-value pairs to percent-encode.
        encoding: The encoding to encode *query*.

    Returns:
        A string in the form application/x-www-form-urlencoded.

    Examples:
        >>> urlencode([('a', 'a'), ('a', 'b'), ('a', 'c')])
        'a=a&a=b&a=c'

        >>> urlencode([('🌈', 'a')])
        '%F0%9F%8C%88=a'

        >>> urlencode([('🌈', 'a')], encoding="windows-1252")
        '%26%23127752%3B=a'  # → '&#127752;=a'

        >>> urlencode([('\ud83c\udf08', 'a')])
        '%F0%9F%8C%88=a'

        >>> urlencode([('\ud83c', 'a')])
        '%EF%BF%BD=a'  # → '\ufffd=a'
    """
    params = []
    for name, value in query:
        name = string_percent_encode(
            name,
            SAFE_URLENCODED_PERCENT_ENCODE_SET,
            encoding=encoding,
            space_as_plus=True,
        )
        value = string_percent_encode(
            value,
            SAFE_URLENCODED_PERCENT_ENCODE_SET,
            encoding=encoding,
            space_as_plus=True,
        )
        params.append(f"{name}={value}")
    return "&".join(params)


def urlparse(
    urlstring: str,
    base: Optional[str] = None,
    encoding: str = "utf-8",
    allow_fragments: bool = True,
) -> ParseResult:
    """An alternative to :func:`urllib.parse.urlparse`.

    Parses a string *urlstring* against a base URL *base* using the basic URL
    parser, and returns :class:`urllib.parse.ParseResult`.

    Args:
        urlstring: An absolute-URL or a relative-URL. If *urlstring* is a
            relative-URL, *base* is required.
        base: An absolute-URL for a relative-URL *urlstring*.
        encoding: The encoding to encode URL’s query. If the encoding fails,
            it will be replaced with the appropriate XML character reference.
        allow_fragments: If *False*, fragment identifiers are not recognized.

    Returns:
        A named tuple :class:`urllib.parse.ParseResult`.

    Raises:
        urlstd.error.URLParseError: Raised when URL parsing fails.

    Examples:
        >>> urlparse('http://user:pass@foo:21/bar;par?b#c')
        ParseResult(scheme='http', netloc='user:pass@foo:21', path='/bar',
        params='par', query='b', fragment='c')

        >>> urlparse('?🌈=a#c', 'http://user:pass@foo:21/bar;par?b#c')
        ParseResult(scheme='http', netloc='user:pass@foo:21', path='/bar',
        params='par', query='%F0%9F%8C%88=a', fragment='c')

        >>> urlparse('?🌈=a#c', 'http://user:pass@foo:21/bar;par?b#c',
        ...     encoding='windows-1252')
        ParseResult(scheme='http', netloc='user:pass@foo:21', path='/bar',
        params='par', query='%26%23127752%3B=a', fragment='c')
    """
    url = parse_url(urlstring, base, encoding)
    hostname = url.serialize_host()
    host = f"{hostname}:{url.port}" if url.port is not None else hostname
    netloc = ""
    if url.includes_credentials():
        netloc += url.username
        if url.password:
            netloc += ":" + url.password
        netloc += "@"
    netloc += host
    pathname = url.serialize_path()
    path, params = (pathname.split(";", maxsplit=1) + [""])[:2]
    query = url.query or ""
    if allow_fragments:
        fragment = url.fragment or ""
    else:
        fragment = "#" + url.fragment if url.fragment else ""
        if len(query) > 0:
            query += fragment
        elif len(params) > 0:
            params += fragment
        else:
            path += fragment
        fragment = ""
    return ParseResult(
        scheme=url.scheme,
        netloc=netloc,
        path=path,
        params=params,
        query=query,
        fragment=fragment,
    )  # noqa


def utf8_decode(b: bytes) -> str:
    """Decodes a byte sequence with utf-8 and returns its string.

    If decoding fails, it will be replaced with U+FFFD.

    Args:
        b: A byte sequence to decode with utf-8.

    Returns:
        A utf-8 decoded string.
    """
    return b.decode("utf-8", "replace")


def utf8_encode(s: str) -> bytes:
    """Encodes a string with utf-8 and returns its byte sequence.

    Invalid surrogates will be replaced with U+FFFD.

    Args:
        s: A string to encode with utf-8.

    Returns:
        A utf-8 encoded byte sequence.
    """
    s = s.encode("utf-16", "surrogatepass").decode("utf-16", "replace")
    return s.encode("utf-8", "strict")


def utf8_percent_encode(s: str, safe: str, space_as_plus: bool = False) -> str:
    """Returns a percent-encoded string after encoding with utf-8.

    Invalid surrogates will be replaced with U+FFFD.
    Also, if the encoding fails, it will be replaced with the appropriate XML
    character reference.

    This is equivalent to
    "string_percent_encode(s, safe,'utf-8', space_as_plus)".

    Args:
        s: A string to percent-encode.
        safe: ASCII characters that should not be percent-encoded.
        space_as_plus: If *True*, replace 0x20 (space) with U+002B (plus sign).

    Returns:
        A percent-encoded string after encoding with utf-8.
    """
    return string_percent_encode(
        s, safe, encoding="utf-8", space_as_plus=space_as_plus
    )


class Host:
    """Utility class for hosts (domains and IP addresses)."""

    @classmethod
    def _ends_in_a_number(cls, host: str) -> bool:
        parts = host.split(".")
        if len(parts[-1]) == 0:
            # if len(parts) == 1:
            #     return False
            del parts[-1]

        last = parts[-1]
        result = cls._parse_ipv4_number(last)
        if result[0] >= 0:
            return True

        if len(last) > 0 and all(c in ASCII_DIGITS for c in last):
            return True
        return False

    @classmethod
    def _parse_ipv4(cls, host: str) -> int:
        log = get_logger(cls)
        validation_error = False
        parts = host.split(".")
        if len(parts[-1]) == 0:
            validation_error = True
            if len(parts) > 1:
                del parts[-1]
        if len(parts) > 4:
            log.error("%r does not appear to be an IPv4 address", host)
            raise IPv4AddressParseError(
                f"{host!r} does not appear to be an IPv4 address"
            )

        numbers = []
        for part in parts:
            result = cls._parse_ipv4_number(part)
            if result[0] < 0:
                log.error("%r does not appear to be an IPv4 address", host)
                raise IPv4AddressParseError(
                    f"{host!r} does not appear to be an IPv4 address"
                )
            validation_error |= result[1]
            numbers.append(result[0])

        if validation_error:
            log.info(
                "Convert string to numbers as IPv4 address: %r → %r",
                host,
                numbers,
            )
        if any(x > 255 for x in numbers):
            log.info(
                "Any parts of IPv4 address are greater than 255: %r %r",
                host,
                numbers,
            )
        if any(x > 255 for x in numbers[:-1]) and numbers[-1] <= 255:
            log.error(
                "Any but the last part of IPv4 address are greater than 255: "
                "%r %r",
                host,
                numbers,
            )
            raise IPv4AddressParseError(
                f"Any but the last part of IPv4 address are greater than 255: "
                f"{host!r} {numbers!r}"
            )
        limit = 256 ** (5 - len(numbers))
        if numbers[-1] >= limit:
            log.error(
                "The last part of IPv4 address is greater than or equal to "
                "%d: %r %r",
                limit,
                host,
                numbers,
            )
            raise IPv4AddressParseError(
                f"The last part of IPv4 address is greater than or equal to "
                f"{limit}: {host!r} {numbers!r}"
            )

        ipv4 = numbers[-1]
        for counter, n in enumerate(numbers[:-1]):
            ipv4 += n * 256 ** (3 - counter)
        return ipv4

    @classmethod
    def _parse_ipv4_number(cls, text: str) -> Tuple[int, bool]:
        validation_error = False
        if len(text) == 0:
            return -1, validation_error

        r = 10
        if len(text) >= 2:
            if text[:2] in ["0x", "0X"]:
                validation_error = True
                text = text[2:]
                r = 16
            elif text[0] == "0":
                validation_error = True
                text = text[1:]
                r = 8
        if len(text) == 0:
            return 0, validation_error

        try:
            return int(text, r), validation_error
        except ValueError:
            validation_error = True
        return -1, validation_error

    @classmethod
    def _parse_ipv6(cls, host: str) -> Tuple[int, ...]:
        # TODO: Implement IPv6 parser?
        #  (https://url.spec.whatwg.org/#concept-ipv6-parser)
        log = get_logger(cls)
        try:
            ipv6 = int(IPv6Address(host))
        except ValueError as e:
            log.error("Invalid IPv6 address: %s", e)
            raise IPv6AddressParseError(f"{e!s}") from None
        address: List[int] = []
        for _ in range(8):
            address.insert(0, ipv6 & 0xFFFF)
            ipv6 >>= 16
        return tuple(address)

    @classmethod
    def _parse_opaque_host(cls, host: str) -> str:
        log = get_logger(cls)
        if any(c in FORBIDDEN_HOST_CODE_POINT_EXCLUDING_PERCENT for c in host):
            log.error(
                "Contains a forbidden host code point excluding '%%' in "
                "opaque host %r",
                host,
            )
            raise HostParseError(
                f"Contains a forbidden host code point excluding '%' in "
                f"opaque host {host!r}"
            )

        parts = [m.group() for m in PERCENT_RE.finditer(host)]
        if not (
            all(len(x) >= 3 for x in parts)
            and all(c in ASCII_HEX_DIGITS for c in (x[1:3] for x in parts))
        ):
            log.info(
                f"Found incorrect percent-encoding in opaque host {host!r}"
            )
        return utf8_percent_encode(host, SAFE_C0_CONTROL_PERCENT_ENCODE_SET)

    @classmethod
    def _serialize_ipv4(cls, address: int) -> str:
        output: List[str] = []
        n = address
        for _ in range(4):
            output.insert(0, str(n % 256))
            n //= 256
        return ".".join(output)

    @classmethod
    def _serialize_ipv6(cls, address: Sequence[int]) -> str:
        assert len(address) == 8
        output = ""

        # find the longest sequence of zeros
        compress = zero_seq_start = None
        max_zero_seq_len = 1
        zero_seq_len = 0
        for piece_index, value in enumerate(address):
            if value == 0:
                if zero_seq_start is None:
                    zero_seq_start = piece_index
                zero_seq_len += 1
            else:
                if zero_seq_len > max_zero_seq_len:
                    compress = zero_seq_start
                    max_zero_seq_len = zero_seq_len
                zero_seq_start = None
                zero_seq_len = 0
        else:
            if zero_seq_len > max_zero_seq_len:
                compress = zero_seq_start

        ignore0 = False
        for piece_index, value in enumerate(address):
            if ignore0 and value == 0:
                continue
            elif ignore0:
                ignore0 = False

            if compress == piece_index:
                separator = "::" if piece_index == 0 else ":"
                output += separator
                ignore0 = True
                continue
            output += f"{value:x}"
            if piece_index != 7:
                output += ":"
        return output

    @classmethod
    def parse(
        cls, host: str, is_not_special: bool = False
    ) -> Union[str, int, Tuple[int, ...]]:
        """Parses a string *host*, and returns a domain, IP address, opaque
        host, or empty host.

        Args:
            host: A host string to parse.
            is_not_special: *True* if a URL’s scheme is not a special scheme,
                *False* otherwise.

        Returns:
            - str -- A domain, an opaque host, or an empty host.
            - int -- An IPv4 address.
            - Tuple[int, ...] -- An IPv6 address.

        Raises:
            urlstd.error.HostParseError: Raised when a host string is not valid.

            urlstd.error.IPv4AddressParseError: Raised when IPv4 address
                parsing fails.

            urlstd.error.IPv6AddressParseError: Raised when IPv6 address
                parsing fails.
        """
        if len(host) == 0:
            return ""  # empty host

        log = get_logger(cls)
        if host.startswith("["):
            # IPv6 address
            if not host.endswith("]"):
                log.error(
                    "Invalid IPv6 address: Unexpected end of input in %r", host
                )
                raise IPv6AddressParseError(
                    f"Unexpected end of input in {host!r}"
                )
            return cls._parse_ipv6(host[1:-1])
        elif is_not_special:
            # opaque host
            return cls._parse_opaque_host(host)

        domain = utf8_decode(string_percent_decode(host))
        ascii_domain = IDNA.domain_to_ascii(domain)
        if any(c in FORBIDDEN_HOST_CODE_POINT for c in ascii_domain):
            log.error(
                "Contains a forbidden host code point in ASCII-domain %r",
                ascii_domain,
            )
            raise HostParseError(
                f"Contains a forbidden host code point in ASCII-domain "
                f"{ascii_domain!r}"
            )

        if cls._ends_in_a_number(ascii_domain):
            # IPv4 address
            return cls._parse_ipv4(ascii_domain)
        return ascii_domain  # ASCII domain

    @classmethod
    def serialize(cls, host: Union[str, int, Sequence[int]]) -> str:
        """Returns a string representation of a host.

        Args:
            host: A domain, an IP address, an opaque host, or an empty host.

        Returns:
            A host string.
        """
        if isinstance(host, int):
            # IPv4 address
            return cls._serialize_ipv4(host)
        elif isinstance(host, (list, tuple)):
            # IPv6 address
            return "[{}]".format(cls._serialize_ipv6(host))
        return host  # type: ignore  # domain, opaque host, or empty host


class IDNA:
    """Utility class for IDNA processing."""

    # References:
    #  https://chromium.googlesource.com/chromium/src/+/refs/tags/99.0.4761.0/url/url_idna_icu.cc
    #  https://svn.webkit.org/repository/webkit/tags/Safari-613.1.9.2/Source/WTF/wtf/URLParser.h

    _ALLOWED_NAME_TO_ASCII_ERRORS = (
        icu.UIDNA_ERROR_HYPHEN_3_4
        | icu.UIDNA_ERROR_LEADING_HYPHEN
        | icu.UIDNA_ERROR_TRAILING_HYPHEN
        | icu.UIDNA_ERROR_EMPTY_LABEL
        | icu.UIDNA_ERROR_LABEL_TOO_LONG
        | icu.UIDNA_ERROR_DOMAIN_NAME_TOO_LONG
    )

    _UIDNA_ERROR_TO_STRING = {
        icu.UIDNA_ERROR_EMPTY_LABEL: "UIDNA_ERROR_EMPTY_LABEL",
        icu.UIDNA_ERROR_LABEL_TOO_LONG: "UIDNA_ERROR_LABEL_TOO_LONG",
        icu.UIDNA_ERROR_DOMAIN_NAME_TOO_LONG: "UIDNA_ERROR_DOMAIN_NAME_TOO_LONG",
        icu.UIDNA_ERROR_LEADING_HYPHEN: "UIDNA_ERROR_LEADING_HYPHEN",
        icu.UIDNA_ERROR_TRAILING_HYPHEN: "UIDNA_ERROR_TRAILING_HYPHEN",
        icu.UIDNA_ERROR_HYPHEN_3_4: "UIDNA_ERROR_HYPHEN_3_4",
        icu.UIDNA_ERROR_LEADING_COMBINING_MARK: "UIDNA_ERROR_LEADING_COMBINING_MARK",
        icu.UIDNA_ERROR_DISALLOWED: "UIDNA_ERROR_DISALLOWED",
        icu.UIDNA_ERROR_PUNYCODE: "UIDNA_ERROR_PUNYCODE",
        icu.UIDNA_ERROR_LABEL_HAS_DOT: "UIDNA_ERROR_LABEL_HAS_DOT",
        icu.UIDNA_ERROR_INVALID_ACE_LABEL: "UIDNA_ERROR_INVALID_ACE_LABEL",
        icu.UIDNA_ERROR_BIDI: "UIDNA_ERROR_BIDI",
        icu.UIDNA_ERROR_CONTEXTJ: "UIDNA_ERROR_CONTEXTJ",
        icu.UIDNA_ERROR_CONTEXTO_PUNCTUATION: "UIDNA_ERROR_CONTEXTO_PUNCTUATION",
        icu.UIDNA_ERROR_CONTEXTO_DIGITS: "UIDNA_ERROR_CONTEXTO_DIGITS",
    }

    _cache: Dict[int, icu.IDNA] = {}

    @classmethod
    def _create_instance(cls, options: int) -> icu.IDNA:
        uts46 = cls._cache.get(options)
        if uts46 is None:
            cls._cache[options] = uts46 = icu.IDNA.create_uts46_instance(
                options
            )
        return uts46

    @classmethod
    def _errors_to_string(cls, errors: int) -> str:
        names = []
        for value, name in cls._UIDNA_ERROR_TO_STRING.items():
            if value & errors:
                names.append(name)
                errors &= ~value
        if errors:
            names.append(hex(errors))
        return "|".join(names)

    @classmethod
    def domain_to_ascii(cls, domain: str, be_strict: bool = False) -> str:
        """Converts a domain name to IDNA ASCII form.

        Args:
            domain: A domain name.
            be_strict: If *True*, set the UseSTD3ASCIIRules flag.
                See :rfc:`3490` for more details.

        Returns:
            A domain name in IDNA ASCII form.

        Raises:
            urlstd.error.HostParseError: Raised when a domain name is not valid.
                See `uidna.h
                <https://unicode-org.github.io/icu-docs/apidoc/released/icu4c/uidna_8h.html>`_
                for more details.

            urlstd.error.IDNAError: Raised when the ICU API returns an error.
                See `UErrorCode
                <https://unicode-org.github.io/icu-docs/apidoc/released/icu4c/utypes_8h.html>`_
                for more details.
        """
        log = get_logger(cls)
        info = icu.IDNAInfo()
        try:
            options = (
                icu.UIDNA_CHECK_BIDI
                | icu.UIDNA_CHECK_CONTEXTJ
                | icu.UIDNA_NONTRANSITIONAL_TO_ASCII
            )
            if be_strict:
                options |= icu.UIDNA_USE_STD3_RULES
            uts46 = cls._create_instance(options)
            dest = icu.UnicodeString()
            uts46.name_to_ascii(
                icu.UnicodeString(domain, len(domain)), dest, info
            )
            errors = info.get_errors()
            if errors & ~cls._ALLOWED_NAME_TO_ASCII_ERRORS:
                error_names = cls._errors_to_string(errors)
                log.error(
                    "Invalid domain name %r: errors=%s (0x%x)",
                    domain,
                    error_names,
                    errors,
                )
                raise HostParseError(
                    f"Invalid domain name {domain!r}: errors={error_names!s} "
                    f"(0x{errors:x})"
                )
            ascii_domain = str(dest)
            if len(ascii_domain) == 0:
                log.error("Empty host after the domain to ASCII: %r", domain)
                raise HostParseError(
                    f"Empty host after the domain to ASCII: {domain!r}"
                )
            return ascii_domain
        except icu.ICUError as e:
            errors = info.get_errors()
            log.error(
                "Unable to convert domain name %r to ASCII form: "
                "%r: errors=0x%x",
                domain,
                e,
                errors,
            )
            raise IDNAError(
                f"Unable to convert domain name {domain!r} to ASCII form: "
                f"{e!r}: errors=0x{errors:x}"
            ) from None


class Origin(NamedTuple):
    """A named tuple that represents the origin of the URL."""

    #: A URL's scheme.
    scheme: str

    #: A URL's host.
    host: Optional[Union[str, int, Tuple[int, ...]]]

    #: A URL's port.
    port: Optional[int]

    #: A URL's domain.
    domain: Optional[str]

    def __str__(self) -> str:
        """Returns a string representation of the origin.

        Returns:
            A string representation of the origin.
        """
        host = "" if self.host is None else Host.serialize(self.host)
        result = f"{self.scheme}://{host}"
        if self.port is not None:
            result += f":{self.port}"
        return result


@dataclass(eq=False)
class URLRecord:
    """A data class that represents a universal identifier."""

    #: A URL's scheme.
    scheme: str = ""

    #: A URL's username.
    username: str = ""

    #: A URL's password.
    password: str = ""

    #: A URL's host.
    host: Optional[Union[str, int, Tuple[int, ...]]] = None

    #: A URL's port.
    port: Optional[int] = None

    #: A URL's path.
    path: Union[List[str], str] = field(default_factory=list)  # type: ignore

    #: A URL's query.
    query: Optional[str] = None

    #: A URL's fragment.
    fragment: Optional[str] = None

    #: A URL's blob URL entry. (unused)
    blob_url_entry: Optional[str] = None

    def __repr__(self) -> str:
        """Returns a nicely formatted representation string."""
        return (
            f"{self.__class__.__name__}("
            f"href={self.href!r}, "
            f"scheme={self.scheme!r}, "
            f"username={self.username!r}, "
            f"password={self.password!r}, "
            f"host={self.host!r}, "
            f"port={self.port!r}, "
            f"path={self.path!r}, "
            f"query={self.query!r}, "
            f"fragment={self.fragment!r}"
            f")"
        )

    def __str__(self) -> str:
        """Returns a string representation of a URL.

        This is equivalent to :attr:`.href`.

        Returns:
            A string representation of a URL.
        """
        return self.href

    def cannot_have_username_password_port(self) -> bool:
        """Returns *True* if a URL's host is *None*, host is the empty string,
        or scheme is "file", *False* otherwise.

        Returns:
            *True* if a URL's host is *None*, host is the empty string,
            or scheme is "file", *False* otherwise.
        """
        return (
            self.host is None
            or (isinstance(self.host, str) and len(self.host) == 0)
            or self.scheme == "file"
        )

    def has_opaque_path(self) -> bool:
        """Returns *True* if a URL's path is a string, *False* otherwise.

        Returns:
            *True* if a URL's path is a string, *False* otherwise.
        """
        return isinstance(self.path, str)

    @property
    def href(self) -> str:
        """Returns a string representation of a URL.

        This is equivalent to :meth:`.serialize_url` with no arguments.
        """
        return self.serialize_url()

    def includes_credentials(self) -> bool:
        """Returns *True* if a URL's username or password is not the empty
        string, *False* otherwise.

        Returns:
            *True* if a URL's username or password is not the empty
            string, *False* otherwise.
        """
        return len(self.username) > 0 or len(self.password) > 0

    def is_not_special(self) -> bool:
        """Returns *True* if a URL's scheme is not a special scheme
        ("ftp", "file", "http", "https", "ws", or "wss"), *False* otherwise.

        Returns:
            *True* if a URL's scheme is not a special scheme
            ("ftp", "file", "http", "https", "ws", or "wss"), *False* otherwise.
        """
        return self.scheme not in SPECIAL_SCHEMES

    def is_special(self) -> bool:
        """Returns *True* if a URL's scheme is a special scheme
        ("ftp", "file", "http", "https", "ws", or "wss"), *False* otherwise.

        Returns:
            *True* if a URL's scheme is a special scheme
            ("ftp", "file", "http", "https", "ws", or "wss"), *False* otherwise.
        """
        return self.scheme in SPECIAL_SCHEMES

    @property
    def origin(self) -> Optional[Origin]:
        """Returns a URL’s origin or *None* as an `opaque origin
        <https://html.spec.whatwg.org/multipage/origin.html#concept-origin-opaque>`_.

        Examples:
            >>> parse_url('blob:https://example.com:443/').origin
            Origin(scheme='https', host='example.com', port=None, domain=None)

            >>> parse_url('blob:d3958f5c-0777-0845-9dcf-2cb28783acaf').origin  # → None

            >>> parse_url('http://example.org:82/foo/bar').origin
            Origin(scheme='http', host='example.org', port=82, domain=None)

            >>> parse_url('non-special://test/x').origin  # → None
        """
        if self.scheme == "blob":
            # TODO: If url’s blob URL entry is non-null, then return url’s blob
            #  URL entry’s environment’s origin.
            if len(self.path) > 0:
                try:
                    url = self.serialize_path()
                    path_url = BasicURLParser.parse(url)
                    return path_url.origin
                except ValueError:
                    pass
            return None
        elif self.scheme in ["ftp", "http", "https", "ws", "wss"]:
            return Origin(self.scheme, self.host, self.port, None)
        return None

    def serialize_host(self) -> str:
        """Returns a string representation of a URL's host.

        Returns:
            A string representation of a URL's host.
        """
        return Host.serialize(self.host) if self.host is not None else ""

    def serialize_path(self) -> str:
        """Returns a string representation of a URL's path.

        Returns:
            A string representation of a URL's path.
        """
        if self.has_opaque_path():
            return self.path  # type: ignore
        output = ""
        for segment in self.path:
            output += f"/{segment}"
        return output

    def serialize_url(self, exclude_fragment: bool = False) -> str:
        """Returns a string representation of a URL.

        Args:
            exclude_fragment: If *True*, fragment identifiers will be removed
                from the output string.

        Returns:
            A string representation of a URL.
        """
        output = self.scheme + ":"
        if self.host is not None:
            output += "//"
            if self.includes_credentials():
                output += self.username
                if self.password:
                    output += ":" + self.password
                output += "@"
            output += Host.serialize(self.host)
            if self.port is not None:
                output += f":{self.port}"
        if (
            self.host is None
            and not self.has_opaque_path()
            and len(self.path) > 1
            and len(self.path[0]) == 0
        ):
            output += "/."
        output += self.serialize_path()
        if self.query is not None:
            output += "?" + self.query
        if not exclude_fragment and self.fragment is not None:
            output += "#" + self.fragment
        return output

    def shorten_path(self) -> None:
        """Shortens a URL's path."""
        assert not self.has_opaque_path()
        path = self.path  # type: ignore
        path_size = len(path)
        if path_size == 0:
            return
        elif (
            self.scheme == "file"
            and path_size == 1
            and is_normalized_windows_drive_letter(path[0])
        ):
            return
        del path[-1]  # type: ignore


class URLSearchParams(collections.abc.Collection):
    """Parses and manipulates URL's query.

    Args:
        init: One of: A string in application/x-www-form-urlencoded form,
            a sequence of name-value pairs,
            a dictionary containing name-value pairs,
            :class:`.URLRecord` object,
            or :class:`.URLSearchParams` object.

    Examples:
        To create a URLSearchParams:

        >>> params = URLSearchParams('?a=1&b=2&a=3')
        >>> list(params)
        [('a', '1'), ('b', '2'), ('a', '3')]

        >>> params = URLSearchParams([('a', '1'), ('b', '2'), ('a', '3')])
        >>> list(params)
        [('a', '1'), ('b', '2'), ('a', '3')]

        >>> params = URLSearchParams({'a': '1', 'b': '2', 'a': '3'})
        >>> list(params)
        [('a', '3'), ('b', '2')]

        >>> new_params = URLSearchParams(params)
        >>> list(new_params)
        [('a', '3'), ('b', '2')]
    """

    @overload
    def __init__(self, init: str) -> None:
        ...

    @overload
    def __init__(
        self, init: Sequence[Sequence[Union[str, int, float]]]
    ) -> None:
        ...

    @overload
    def __init__(self, init: Dict[str, Union[str, int, float]]) -> None:
        ...

    @overload
    def __init__(self, init: URLRecord) -> None:
        ...

    @overload
    def __init__(self, init: "URLSearchParams") -> None:
        ...

    @overload
    def __init__(self) -> None:
        ...

    def __init__(
        self,
        init: Optional[
            Union[
                str,
                Sequence[Sequence[Union[str, int, float]]],
                Dict[str, Union[str, int, float]],
                URLRecord,
                "URLSearchParams",
            ]
        ] = None,
    ) -> None:
        self._list: List[Tuple[str, str]] = []
        self._url: Optional[URLRecord] = None
        if init is None:
            return
        elif isinstance(init, (list, tuple)):
            if any(len(x) != 2 for x in init):
                raise ValueError(
                    f"Expected a sequence of name-value pairs, but got {init}"
                )
            for name, value in init:
                self._list.append(
                    (
                        utf8_decode(utf8_encode(str(name))),
                        utf8_decode(utf8_encode(str(value))),
                    )
                )
            return
        elif isinstance(init, dict):
            temp = {}
            for name, value in init.items():
                temp[utf8_decode(utf8_encode(str(name)))] = utf8_decode(
                    utf8_encode(str(value))
                )
            for name, value in temp.items():
                self._list.append((name, value))
            return
        elif isinstance(init, URLRecord):
            self.attach(init)
            return
        elif isinstance(init, URLSearchParams):
            init = str(init)
        elif not isinstance(init, str):
            raise TypeError(f"Expected string, not {type(init).__name__}")

        if init.startswith("?"):
            init = init[1:]
        self._list += parse_qsl(utf8_encode(init))

    def __add__(self, other: Any) -> str:
        """Returns a string in application/x-www-form-urlencoded form
        concatenated with *other*.

        *other* must be a string.

        Args:
            other: A string to concatenate.

        Returns:
            A string in application/x-www-form-urlencoded form
            concatenated with *other*.
        """
        if not isinstance(other, str):
            return NotImplemented
        return self._serialize_query() + other

    def __contains__(self, item: Any) -> bool:
        """Returns *True* if a name-value pair with the specified *item* exists,
        *False* otherwise.

        *item* must be a string.

        This is equivalent to :meth:`.has`.

        Args:
            item: The name of parameter to find.

        Returns:
            *True* if a name-value pair with the specified *item* exists,
            *False* otherwise.
        """
        if not isinstance(item, str):
            raise TypeError(
                f"Requires string as left operand, not {type(item).__name__}"
            )
        return self.get(item) is not None

    def __iter__(self) -> Iterator[Tuple[str, str]]:
        """Returns a new iterator of this object’s items
        ((name, value) pairs).

        This is equivalent to :meth:`.entries`.

        Returns:
            An iterator of this object’s items ((name, value) pairs).
        """
        return iter(self._list)

    def __len__(self) -> int:
        """Returns the number of name-value pairs.

        Returns:
            The number of name-value pairs.
        """
        return len(self._list)

    def __repr__(self) -> str:
        """Returns a nicely formatted representation string."""
        return f"{self.__class__.__name__}({self._list})"

    def __str__(self) -> str:
        """Returns a string in application/x-www-form-urlencoded form.

        Returns:
            A string in application/x-www-form-urlencoded form.
        """
        return self._serialize_query()

    def _serialize_query(self) -> str:
        return urlencode(self._list)

    def _update(self) -> None:
        if self._url is None:
            return
        serialized_query = self._serialize_query()
        self._url.query = (
            serialized_query if len(serialized_query) > 0 else None
        )

    def append(self, name: str, value: Union[str, int, float]) -> None:
        """Appends a new name-value pair as a new search parameter.

        Args:
            name: The name of parameter to append.
            value: The value of parameter to append.

        Examples:
            >>> params = URLSearchParams()
            >>> params.append('a', '1')
            >>> params.append('b', '2')
            >>> params.append('a', '3')
            >>> list(params)
            [('a', '1'), ('b', '2'), ('a', '3')]
        """
        name = utf8_decode(string_percent_decode(name))
        value = utf8_decode(string_percent_decode(str(value)))
        self._list.append((name, value))
        self._update()

    def attach(self, init: URLRecord) -> None:
        """Associates a URL record *init* with this URLSearchParams object.

        Args:
            init: The URL record to associate with.
        """
        query = init.query or ""
        self._list = parse_qsl(utf8_encode(query))
        self._url = init

    def delete(self, name: str) -> None:
        """Removes all name-value pairs whose name is *name*.

        Args:
            name: The name of parameter to delete.

        Examples:
            >>> params = URLSearchParams('a=1&b=2&a=3')
            >>> list(params)
            [('a', '1'), ('b', '2'), ('a', '3')]
            >>> params.delete('a')
            >>> list(params)
            [('b', '2')]
        """
        name = utf8_decode(string_percent_decode(name))
        for i, name_value in reversed(list(enumerate(self._list))):
            if name_value[0] == name:
                self._list.pop(i)
        self._update()

    def entries(self) -> Iterator[Tuple[str, str]]:
        """Returns a new iterator of this object’s items
        ((name, value) pairs).

        This is equivalent to :meth:`.__iter__`.

        Returns:
            An iterator of this object’s items ((name, value) pairs).
        """
        return iter(self._list)

    def get(self, name: str) -> Optional[str]:
        """Returns the value of the first name-value pair whose name is *name*,
        or *None* if not exists.

        Args:
            name: The name of parameter to return.

        Returns:
            The value of the first name-value pair whose name is *name*,
            or *None* if not exists.

        Examples:
            >>> params = URLSearchParams('a=1&b=2&a=3')
            >>> params.get('a')
            '1'
            >>> params.get('c')  # → None
        """
        name = utf8_decode(string_percent_decode(name))
        for name_value in self._list:
            if name_value[0] == name:
                return name_value[1]
        return None

    def get_all(self, name: str) -> Tuple[str, ...]:
        """Returns the values of all name-value pairs whose name is *name*,
        or the empty tuple if not exists.

        Args:
            name: The name of parameter to return.

        Returns:
            The values of all name-value pairs whose name is *name*,
            or the empty tuple if not exists.

        Examples:
            >>> params = URLSearchParams('a=1&b=2&a=3')
            >>> params.get_all('a')
            ('1', '3')
            >>> params.get_all('c')
            ()
        """
        name = utf8_decode(string_percent_decode(name))
        return tuple(
            [
                name_value[1]
                for name_value in self._list
                if name_value[0] == name
            ]
        )

    def has(self, name: str) -> bool:
        """Returns *True* if a name-value pair with the specified *name* exists,
        *False* otherwise.

        This is equivalent to :meth:`.__contains__`.

        Args:
            name: The name of parameter to find.

        Returns:
            *True* if a name-value pair with the specified *name* exists,
            *False* otherwise.
        """
        return self.get(name) is not None

    def keys(self) -> Iterator[str]:
        """Returns a new iterator of this object’s names.

        Returns:
            An iterator of this object’s names.
        """
        return iter([name_value[0] for name_value in self._list])

    def set(self, name: str, value: Union[str, int, float]) -> None:
        """If name-value pair with the specified name exists, sets the value of
        the first name-value pair whose name is *name* to *value* and remove
        the other values. Otherwise, appends a new name-value pair.

        Args:
            name: The name of parameter to set.
            value: The value of parameter to set.

        Examples:
            >>> params = URLSearchParams('a=1&b=2&a=3')
            >>> list(params)
            [('a', '1'), ('b', '2'), ('a', '3')]
            >>> params.set('a', '4')
            >>> list(params)
            [('a', '4'), ('b', '2')]
        """
        name = utf8_decode(string_percent_decode(name))
        value = utf8_decode(string_percent_decode(str(value)))
        items = self._list
        found = -1
        for index, name_value in enumerate(items):
            if name_value[0] == name:
                found = index
                items[index] = name, value
                break
        if found == -1:
            items.append((name, value))
        else:
            index = len(items) - 1
            while index > found:
                if items[index][0] == name:
                    del items[index]
                index -= 1
        self._update()

    def sort(self) -> None:
        """Sorts all name-value pairs by comparison of code units.

        The relative order between name-value pairs with equal names will be
        preserved.

        Examples:
            >>> params = URLSearchParams('ﬃ&🌈')
            >>> list(params)
            [('ﬃ', ''), ('🌈', '')]
            >>> params.sort()
            # code point: 'ﬃ' (0xFB03) < '🌈' (0x1F308), but
            # code units: '🌈' (0xD83C, 0xDF08) < 'ﬃ' (0xFB03)
            >>> list(params)
            [('🌈', ''), ('ﬃ', '')]
        """
        self._list.sort(
            key=lambda x: icu.UnicodeString(  # type: ignore
                x[0],
                len(x[0]),
            )
        )
        self._update()

    def values(self) -> Iterator[str]:
        """Returns a new iterator of this object’s values.

        Returns:
            An iterator of this object’s values.
        """
        return iter([name_value[1] for name_value in self._list])


class URL:
    r"""Parses a string *url* against a base URL *base*.

    Args:
        url: An absolute-URL or a relative-URL.
            If *url* is a relative-URL, *base* is required.
        base: An absolute-URL for a relative-URL *url*.

    Raises:
        urlstd.error.URLParseError: Raised when URL parsing fails.

    Examples:
        To parse a string into a URL with using a base URL:

        >>> URL('//foo/bar', 'http://example.org/foo/bar')
        URL(href='http://foo/bar', origin='http://foo', protocol='http:',
        username='', password='', host='foo', hostname='foo', port='',
        pathname='/bar', search='', hash='')

        >>> URL('/', 'http://example.org/foo/bar')
        URL(href='http://example.org/', origin='http://example.org',
        protocol='http:', username='', password='', host='example.org',
        hostname='example.org', port='', pathname='/', search='', hash='')

        >>> URL('https://test:@test', 'about:blank')
        URL(href='https://test@test/', origin='https://test',
        protocol='https:', username='test', password='', host='test',
        hostname='test', port='', pathname='/', search='', hash='')

        >>> URL('?a=b&c=d', 'http://example.org/foo/bar')
        URL(href='http://example.org/foo/bar?a=b&c=d',
        origin='http://example.org', protocol='http:', username='', password='',
        host='example.org', hostname='example.org', port='',
        pathname='/foo/bar', search='?a=b&c=d', hash='')

        >>> URL('#β', 'http://example.org/foo/bar')
        URL(href='http://example.org/foo/bar#%CE%B2',
        origin='http://example.org', protocol='http:', username='', password='',
        host='example.org', hostname='example.org', port='',
        pathname='/foo/bar', search='', hash='#%CE%B2')

        >>> URL('', 'http://example.org/foo/bar')
        URL(href='http://example.org/foo/bar', origin='http://example.org',
        protocol='http:', username='', password='', host='example.org',
        hostname='example.org', port='', pathname='/foo/bar', search='',
        hash='')

        >>> URL('https://x/\ufffd?\ufffd#\ufffd', 'about:blank')
        URL(href='https://x/%EF%BF%BD?%EF%BF%BD#%EF%BF%BD', origin='https://x',
        protocol='https:', username='', password='', host='x', hostname='x',
        port='', pathname='/%EF%BF%BD', search='?%EF%BF%BD', hash='#%EF%BF%BD')
    """

    def __init__(self, url: str, base: Optional[str] = None):
        self._url: URLRecord = parse_url(url, base=base)
        self._query: URLSearchParams = URLSearchParams(self._url)

    def __repr__(self) -> str:
        """Returns a nicely formatted representation string."""
        return (
            f"{self.__class__.__name__}("
            f"href={self.href!r}, "
            f"origin={self.origin!r}, "
            f"protocol={self.protocol!r}, "
            f"username={self.username!r}, "
            f"password={self.password!r}, "
            f"host={self.host!r}, "
            f"hostname={self.hostname!r}, "
            f"port={self.port!r}, "
            f"pathname={self.pathname!r}, "
            f"search={self.search!r}, "
            f"hash={self.hash!r}"
            f")"
        )

    def __str__(self) -> str:
        """Returns a string representation of a URL.

        This is equivalent to :attr:`.href`.

        Returns:
            A string representation of a URL.
        """
        return self.href

    @property
    def hash(self) -> str:
        """A URL's fragment (includes leading U+0023 (#) if non-empty).

        Examples:
            >>> url = URL('http://example.net')
            >>> str(url)
            'http://example.net/'
            >>> url.hash
            ''
            >>> url.hash = '%c3%89té'
            >>> url.hash
            '#%c3%89t%C3%A9'
            >>> str(url)
            'http://example.net/#%c3%89t%C3%A9'
        """
        fragment = self._url.fragment
        if fragment is None or len(fragment) == 0:
            return ""
        return "#" + fragment

    @hash.setter
    def hash(self, value: str) -> None:
        url = self._url
        if len(value) == 0:
            url.fragment = None
            return
        elif value.startswith("#"):
            value = value[1:]
        url.fragment = ""
        BasicURLParser.parse(
            value, url=url, state_override=URLParserState.FRAGMENT_STATE
        )

    @property
    def host(self) -> str:
        """A URL’s host, and then, if a URL’s port is different from the
        default port for a URL's scheme, U+003A (:), followed by URL’s port.

        If a URL has an
        `opaque path <https://url.spec.whatwg.org/#url-opaque-path>`_,
        setting the value has no effect.

        Examples:
            >>> url = URL('http://example.net')
            >>> str(url)
            'http://example.net/'
            >>> url.host
            'example.net'
            >>> url.host = 'example.com:8080'
            >>> url.host
            'example.com:8080'
            >>> str(url)
            'http://example.com:8080/'
        """
        host = self._url.host
        if host is None:
            return ""
        host = Host.serialize(host)
        port = self._url.port
        if port is None:
            return host
        return f"{host}:{port}"

    @host.setter
    def host(self, value: str) -> None:
        if self._url.has_opaque_path():
            return
        BasicURLParser.parse(
            value, url=self._url, state_override=URLParserState.HOST_STATE
        )

    @property
    def hostname(self) -> str:
        """A URL's host.

        If a URL has an
        `opaque path <https://url.spec.whatwg.org/#url-opaque-path>`_,
        setting the value has no effect.

        Examples:
            >>> url = URL('http://example.net:8080')
            >>> str(url)
            'http://example.net:8080/'
            >>> url.hostname
            'example.net'
            >>> url.hostname = 'example.com'
            >>> url.hostname
            'example.com'
            >>> str(url)
            'http://example.com:8080/'
        """
        return self._url.serialize_host()

    @hostname.setter
    def hostname(self, value: str) -> None:
        if self._url.has_opaque_path():
            return
        BasicURLParser.parse(
            value, url=self._url, state_override=URLParserState.HOSTNAME_STATE
        )

    @property
    def href(self) -> str:
        """A string representation of a URL.

        Must be an absolute-URL when setting a value.

        Examples:
            >>> url = URL('http://example.org/foo/bar')
            >>> url.href
            'http://example.org/foo/bar'
            >>> url.href = 'http:/example.com/'
            >>> url.href
            'http://example.com/'
        """
        return str(self._url)

    @href.setter
    def href(self, value: str) -> None:
        self._url = BasicURLParser.parse(value)
        self._query.attach(self._url)

    @property
    def origin(self) -> str:
        """Returns a string representation of a URL's origin.

        Examples:
            >>> URL('blob:https://example.com:443/').origin
            'https://example.com'

            >>> URL('blob:d3958f5c-0777-0845-9dcf-2cb28783acaf').origin
            'null'

            >>> URL('http://example.org:82/foo/bar').origin
            'http://example.org:82'

            >>> URL('non-special://test/x').origin
            'null'
        """
        origin = self._url.origin
        if origin is None:
            return "null"
        return str(origin)

    @property
    def password(self) -> str:
        """A URL's password.

        If a URL can't have a username/password/port, setting the value has no
        effect.

        Examples:
            >>> url = URL('http://example.net')
            >>> str(url)
            'http://example.net/'
            >>> url.password
            ''
            >>> url.password = '%c3%89té'
            >>> url.password
            '%c3%89t%C3%A9'
            >>> str(url)
            'http://:%c3%89t%C3%A9@example.net/'
        """
        return self._url.password

    @password.setter
    def password(self, value: str) -> None:
        if self._url.cannot_have_username_password_port():
            return
        self._url.password = utf8_percent_encode(
            value, SAFE_USERINFO_PERCENT_ENCODE_SET
        )

    @property
    def pathname(self) -> str:
        """A URL's path.

        If a URL has an
        `opaque path <https://url.spec.whatwg.org/#url-opaque-path>`_,
        setting the value has no effect.

        Examples:
            >>> url = URL('http://example.net')
            >>> str(url)
            'http://example.net/'
            >>> url.pathname
            '/'
            >>> url.pathname = '%2e%2E%c3%89té'
            >>> url.pathname
            '/%2e%2E%c3%89t%C3%A9'
            >>> str(url)
            'http://example.net/%2e%2E%c3%89t%C3%A9'
        """
        return self._url.serialize_path()

    @pathname.setter
    def pathname(self, value: str) -> None:
        if self._url.has_opaque_path():
            return
        self._url.path = []
        BasicURLParser.parse(
            value,
            url=self._url,
            state_override=URLParserState.PATH_START_STATE,
        )

    @property
    def port(self) -> str:
        """A URL's port.

        If a URL can't have a username/password/port, setting the value has no
        effect.

        Examples:
            >>> url = URL('http://example.net:8080')
            >>> str(url)
            'http://example.net:8080/'
            >>> url.port
            '8080'
            >>> url.port = '80'
            >>> url.port
            ''
            >>> str(url)
            'http://example.net/'
        """
        port = self._url.port
        if port is None:
            return ""
        return str(port)

    @port.setter
    def port(self, value: str) -> None:
        if self._url.cannot_have_username_password_port():
            return
        elif len(value) == 0:
            self._url.port = None
            return
        BasicURLParser.parse(
            value, url=self._url, state_override=URLParserState.PORT_STATE
        )

    @property
    def protocol(self) -> str:
        """A URL's scheme, followed by
        U+003A (:).

        Examples:
            >>> url = URL('a://example.net')
            >>> str(url)
            'a://example.net'
            >>> url.protocol
            'a:'
            >>> url.protocol = 'B'
            >>> url.protocol
            'b:'
            >>> str(url)
            'b://example.net'
        """
        return self._url.scheme + ":"

    @protocol.setter
    def protocol(self, value: str) -> None:
        BasicURLParser.parse(
            value + ":",
            url=self._url,
            state_override=URLParserState.SCHEME_START_STATE,
        )

    @property
    def search(self) -> str:
        """A URL's query (includes leading U+003F (?) if non-empty).

        Examples:
            >>> url = URL('http://example.net')
            >>> str(url)
            'http://example.net/'
            >>> url.search
            ''
            >>> url.search = '%c3%89té'
            >>> url.search
            '?%c3%89t%C3%A9'
            >>> str(url)
            'http://example.net/?%c3%89t%C3%A9'
        """
        query = self._url.query
        if query is None or len(query) == 0:
            return ""
        return "?" + query

    @search.setter
    def search(self, value: str) -> None:
        url = self._url
        if len(value) == 0:
            url.query = None
        else:
            if value.startswith("?"):
                value = value[1:]
            url.query = ""
            BasicURLParser.parse(
                value, url=url, state_override=URLParserState.QUERY_STATE
            )
        self._query.attach(url)

    @property
    def search_params(self) -> URLSearchParams:
        """Returns a URLSearchParams object associated with this URL object.

        Examples:
            >>> url = URL('http://example.net/file')
            >>> str(url)
            'http://example.net/file'
            >>> url.search
            ''
            >>> params = url.search_params
            >>> params.append('a', '1')
            >>> params.append('b', '2')
            >>> params.append('a', '3')
            >>> list(params)
            [('a', '1'), ('b', '2'), ('a', '3')]
            >>> url.search
            '?a=1&b=2&a=3'
            >>> str(url)
            'http://example.net/file?a=1&b=2&a=3'
        """
        return self._query

    @property
    def username(self) -> str:
        """A URL's username.

        If a URL can't have a username/password/port, setting the value has no
        effect.

        Examples:
            >>> url = URL('http://example.net')
            >>> str(url)
            'http://example.net/'
            >>> url.username
            ''
            >>> url.username = '%c3%89té'
            >>> url.username
            '%c3%89t%C3%A9'
            >>> str(url)
            'http://%c3%89t%C3%A9@example.net/'
        """
        return self._url.username

    @username.setter
    def username(self, value: str) -> None:
        if self._url.cannot_have_username_password_port():
            return
        self._url.username = utf8_percent_encode(
            value, SAFE_USERINFO_PERCENT_ENCODE_SET
        )


class URLParserState(enum.IntEnum):
    """State machine enums for the basic URL parser."""

    EOF = -1
    AUTHORITY_STATE = 1
    FILE_HOST_STATE = enum.auto()
    FILE_SLASH_STATE = enum.auto()
    FILE_STATE = enum.auto()
    FRAGMENT_STATE = enum.auto()
    HOSTNAME_STATE = enum.auto()
    HOST_STATE = enum.auto()
    NO_SCHEME_STATE = enum.auto()
    OPAQUE_PATH_STATE = enum.auto()
    PATH_OR_AUTHORITY_STATE = enum.auto()
    PATH_START_STATE = enum.auto()
    PATH_STATE = enum.auto()
    PORT_STATE = enum.auto()
    QUERY_STATE = enum.auto()
    RELATIVE_SLASH_STATE = enum.auto()
    RELATIVE_STATE = enum.auto()
    SCHEME_START_STATE = enum.auto()
    SCHEME_STATE = enum.auto()
    SPECIAL_AUTHORITY_IGNORE_SLASHES_STATE = enum.auto()
    SPECIAL_AUTHORITY_SLASHES_STATE = enum.auto()
    SPECIAL_RELATIVE_OR_AUTHORITY_STATE = enum.auto()


class BasicURLParser:
    """An implementation of the
    `basic URL parser <https://url.spec.whatwg.org/#concept-basic-url-parser>`_
    in Python.
    """

    @classmethod
    def _parse_authority(
        cls,
        urlstring: str,
        start: int,
        base: Optional[URLRecord],
        url: URLRecord,
    ) -> Tuple[URLParserState, int]:
        # **authority state**
        _ = base
        log = get_logger(cls)
        index = start
        buffer = ""
        at_sign_seen = False
        password_token_seen = False
        for c in cpstream(urlstring[index:]):
            index += 1
            if c == "@":
                log.info(
                    "Found %r in %r at position %d", c, urlstring, index - 1
                )
                if at_sign_seen:
                    buffer = "%40" + buffer
                at_sign_seen = True
                if password_token_seen:
                    username, password = "", buffer
                else:
                    n = buffer.find(":")
                    if n == -1:
                        username, password = buffer, ""
                    else:
                        password_token_seen = True
                        username, password = buffer[:n], buffer[n + 1 :]
                if len(username) > 0:
                    url.username += utf8_percent_encode(
                        username, SAFE_USERINFO_PERCENT_ENCODE_SET
                    )
                if len(password) > 0:
                    url.password += utf8_percent_encode(
                        password, SAFE_USERINFO_PERCENT_ENCODE_SET
                    )
                buffer = ""
            elif (
                iseof(c) or iscp(c, "/?#") or (url.is_special() and c == "\\")
            ):
                if at_sign_seen and len(buffer) == 0:
                    log.error("Invalid username or password in %r", urlstring)
                    raise URLParseError(
                        f"Invalid username or password in {urlstring!r}"
                    )
                index -= len(buffer) + 1
                # return URLParserState.HOST_STATE, index
                break
            else:
                buffer += c
        return URLParserState.HOST_STATE, index

    @classmethod
    def _parse_file(
        cls,
        urlstring: str,
        start: int,
        base: Optional[URLRecord],
        url: URLRecord,
    ) -> Tuple[URLParserState, int]:
        # **file state**
        log = get_logger(cls)
        url.scheme = "file"
        url.host = ""
        index = start
        c = urlstring[index : index + 1]
        index += 1
        if iscp(c, "/\\"):
            if c == "\\":
                log.info(
                    "Expected '/' but got %r in %r at position %d",
                    c,
                    urlstring,
                    index - 1,
                )
            return URLParserState.FILE_SLASH_STATE, index
        elif base and base.scheme == "file":
            url.host = base.host
            url.path = copy.copy(base.path)
            url.query = base.query
            if c == "?":
                url.query = ""
                return URLParserState.QUERY_STATE, index
            elif c == "#":
                url.fragment = ""
                return URLParserState.FRAGMENT_STATE, index
            elif not iseof(c):
                url.query = None
                if not starts_with_windows_drive_letter(
                    urlstring[index - 1 :]
                ):
                    url.shorten_path()
                else:
                    log.info(
                        "Unexpected Windows drive letter in %r at position %d",
                        urlstring,
                        index - 1,
                    )
                    url.path = []
                return URLParserState.PATH_STATE, index - 1
        return URLParserState.PATH_STATE, index - 1

    @classmethod
    def _parse_file_host(
        cls,
        urlstring: str,
        start: int,
        base: Optional[URLRecord],
        url: URLRecord,
        state_override: Optional[URLParserState],
    ) -> Tuple[URLParserState, int]:
        # **file host state**
        _ = base
        log = get_logger(cls)
        buffer = ""
        index = start
        for c in cpstream(urlstring[index:]):
            index += 1
            if iseof(c) or iscp(c, "/\\?#"):
                index -= 1
                if state_override is None and is_windows_drive_letter(buffer):
                    log.info(
                        "Unexpected Windows drive letter in %r at position %d",
                        urlstring,
                        index - len(buffer),
                    )
                    return URLParserState.PATH_STATE, index - len(buffer)
                elif len(buffer) == 0:
                    url.host = ""
                    if state_override:
                        return URLParserState.EOF, index
                    return URLParserState.PATH_START_STATE, index
                else:
                    host = Host.parse(buffer, url.is_not_special())
                    if host == "localhost":
                        host = ""
                    url.host = host
                    if state_override:
                        return URLParserState.EOF, index
                    # return URLParserState.PATH_START_STATE, index
                    break
            else:
                buffer += c
        return URLParserState.PATH_START_STATE, index

    @classmethod
    def _parse_file_slash(
        cls,
        urlstring: str,
        start: int,
        base: Optional[URLRecord],
        url: URLRecord,
    ) -> Tuple[URLParserState, int]:
        # **file slash state**
        log = get_logger(cls)
        index = start
        c = urlstring[index : index + 1]
        index += 1
        if iscp(c, "/\\"):
            if c == "\\":
                log.info(
                    "Expected '/' but got %r in %r at position %d",
                    c,
                    urlstring,
                    index - 1,
                )
            return URLParserState.FILE_HOST_STATE, index
        else:
            if base and base.scheme == "file":
                url.host = base.host
                if not starts_with_windows_drive_letter(
                    urlstring[index - 1 :]
                ) and (
                    len(base.path) > 0
                    and is_normalized_windows_drive_letter(base.path[0])
                ):
                    assert isinstance(url.path, list)
                    url.path.append(base.path[0])
            return URLParserState.PATH_STATE, index - 1

    @classmethod
    def _parse_fragment(
        cls,
        urlstring: str,
        start: int,
        base: Optional[URLRecord],
        url: URLRecord,
    ) -> Tuple[URLParserState, int]:
        # **fragment state**
        _ = base
        log = get_logger(cls)
        buffer = ""
        index = start
        for c in cpstream(urlstring[index:]):
            index += 1
            if not iseof(c):
                # TODO: If c is not a URL code point and not U+0025 (%),
                #  validation error.
                if c == "%" and any(
                    x not in ASCII_HEX_DIGITS
                    for x in urlstring[index : index + 2]
                ):
                    log.info(
                        "Found incorrect percent-encoding in %r at position %d",
                        urlstring,
                        index - 1,
                    )
                buffer += c
            else:
                index -= 1
                if len(buffer) > 0:
                    url.fragment += utf8_percent_encode(  # type: ignore
                        buffer, SAFE_FRAGMENT_PERCENT_ENCODE_SET
                    )
                break
        return URLParserState.EOF, index

    @classmethod
    def _parse_host(
        cls,
        urlstring: str,
        start: int,
        base: Optional[URLRecord],
        url: URLRecord,
        state_override: Optional[URLParserState],
    ) -> Tuple[URLParserState, int]:
        # **host state**
        # **hostname state**
        _ = base
        if state_override and url.scheme == "file":
            return URLParserState.FILE_HOST_STATE, start

        log = get_logger(cls)
        buffer = ""
        index = start
        inside_brackets = False
        for c in cpstream(urlstring[index:]):
            index += 1
            if c == ":" and not inside_brackets:
                if len(buffer) == 0:
                    log.error("Unexpected empty host in %r", urlstring)
                    raise URLParseError(
                        f"Unexpected empty host in {urlstring!r}"
                    )
                if state_override == URLParserState.HOSTNAME_STATE:
                    return URLParserState.EOF, index - 1
                url.host = Host.parse(buffer, url.is_not_special())
                return URLParserState.PORT_STATE, index
            elif (
                iseof(c) or iscp(c, "/?#") or (url.is_special() and c == "\\")
            ):
                index -= 1
                if url.is_special() and len(buffer) == 0:
                    log.error("Unexpected empty host in %r", urlstring)
                    raise URLParseError(
                        f"Unexpected empty host in {urlstring!r}"
                    )
                elif (
                    state_override
                    and len(buffer) == 0
                    and (url.includes_credentials() or url.port)
                ):
                    return URLParserState.EOF, index
                url.host = Host.parse(buffer, url.is_not_special())
                if state_override:
                    return URLParserState.EOF, index
                # return URLParserState.PATH_START_STATE, index
                break
            else:
                if c == "[":
                    inside_brackets = True
                elif c == "]":
                    inside_brackets = False
                buffer += c
        return URLParserState.PATH_START_STATE, index

    @classmethod
    def _parse_no_scheme(
        cls,
        urlstring: str,
        start: int,
        base: Optional[URLRecord],
        url: URLRecord,
    ) -> Tuple[URLParserState, int]:
        # **no scheme state**
        log = get_logger(cls)
        index = start
        c = urlstring[index : index + 1]
        index += 1
        if base is None or (base.has_opaque_path() and c != "#"):
            log.error("URL scheme not found in %r", urlstring)
            raise URLParseError(f"URL scheme not found in {urlstring!r}")
        elif base.has_opaque_path() and c == "#":
            url.scheme = base.scheme
            url.path = copy.copy(base.path)
            url.query = base.query
            url.fragment = ""
            return URLParserState.FRAGMENT_STATE, index
        elif base.scheme != "file":
            return URLParserState.RELATIVE_STATE, index - 1
        return URLParserState.FILE_STATE, index - 1

    @classmethod
    def _parse_opaque_path(
        cls,
        urlstring: str,
        start: int,
        base: Optional[URLRecord],
        url: URLRecord,
    ) -> Tuple[URLParserState, int]:
        # **opaque path state**
        _ = base
        log = get_logger(cls)
        index = start
        # TODO: Use buffer.
        for c in cpstream(urlstring[index:]):
            index += 1
            if c == "?":
                url.query = ""
                return URLParserState.QUERY_STATE, index
            elif c == "#":
                url.fragment = ""
                return URLParserState.FRAGMENT_STATE, index
            else:
                # TODO: If c is not the EOF code point, not a URL code point,
                #  and not U+0025 (%), validation error.
                if c == "%" and any(
                    x not in ASCII_HEX_DIGITS
                    for x in urlstring[index : index + 2]
                ):
                    log.info(
                        "Found incorrect percent-encoding in %r at position %d",
                        urlstring,
                        index - 1,
                    )
                if iseof(c):
                    # return URLParserState.EOF, index - 1
                    break
                else:
                    url.path += utf8_percent_encode(  # type: ignore
                        c, SAFE_C0_CONTROL_PERCENT_ENCODE_SET
                    )
        return URLParserState.EOF, index - 1

    @classmethod
    def _parse_path(
        cls,
        urlstring: str,
        start: int,
        base: Optional[URLRecord],
        url: URLRecord,
        state_override: Optional[URLParserState],
    ) -> Tuple[URLParserState, int]:
        # **path state**
        _ = base
        log = get_logger(cls)
        buffer = ""
        index = start
        for c in cpstream(urlstring[index:]):
            index += 1
            if (
                (iseof(c) or c == "/")
                or (url.is_special() and c == "\\")
                or (state_override is None and iscp(c, "?#"))
            ):
                if url.is_special() and c == "\\":
                    log.info(
                        "Expected '/' but got %r in %r at position %d",
                        c,
                        urlstring,
                        index - 1,
                    )

                buffer = utf8_percent_encode(
                    buffer, SAFE_PATH_PERCENT_ENCODE_SET
                )
                if buffer in DOUBLE_DOT_PATH_SEGMENTS:
                    url.shorten_path()
                    if c != "/" and not (url.is_special() and c == "\\"):
                        url.path.append("")  # type: ignore
                elif (
                    buffer in SINGLE_DOT_PATH_SEGMENTS
                    and c != "/"
                    and not (url.is_special() and c == "\\")
                ):
                    url.path.append("")  # type: ignore
                elif buffer not in SINGLE_DOT_PATH_SEGMENTS:
                    if (
                        url.scheme == "file"
                        and len(url.path) == 0
                        and is_windows_drive_letter(buffer)
                    ):
                        buffer = buffer[0] + ":"
                    url.path.append(buffer)  # type: ignore
                buffer = ""
                if iseof(c):
                    # return URLParserState.OPAQUE_PATH_STATE, index - 1
                    break
                elif c == "?":
                    url.query = ""
                    return URLParserState.QUERY_STATE, index
                elif c == "#":
                    url.fragment = ""
                    return URLParserState.FRAGMENT_STATE, index
            else:
                # TODO: If c is not a URL code point and not U+0025 (%),
                #  validation error.
                if c == "%" and any(
                    x not in ASCII_HEX_DIGITS
                    for x in urlstring[index : index + 2]
                ):
                    log.info(
                        "Found incorrect percent-encoding in %r at position %d",
                        urlstring,
                        index - 1,
                    )
                buffer += c
        return URLParserState.OPAQUE_PATH_STATE, index - 1

    @classmethod
    def _parse_path_or_authority(
        cls,
        urlstring: str,
        start: int,
        base: Optional[URLRecord],
        url: URLRecord,
    ) -> Tuple[URLParserState, int]:
        # **path or authority state**
        _ = base, url
        index = start
        c = urlstring[index : index + 1]
        index += 1
        if c == "/":
            return URLParserState.AUTHORITY_STATE, index
        return URLParserState.PATH_STATE, index - 1

    @classmethod
    def _parse_path_start(
        cls,
        urlstring: str,
        start: int,
        base: Optional[URLRecord],
        url: URLRecord,
        state_override: Optional[URLParserState],
    ) -> Tuple[URLParserState, int]:
        # **path start state**
        _ = base
        log = get_logger(cls)
        index = start
        c = urlstring[index : index + 1]
        index += 1
        if url.is_special():
            if c == "\\":
                log.info(
                    "Expected '/' but got %r in %r at position %d",
                    c,
                    urlstring,
                    index - 1,
                )
            if not iscp(c, "/\\"):
                index -= 1
            return URLParserState.PATH_STATE, index
        elif state_override is None and c == "?":
            url.query = ""
            return URLParserState.QUERY_STATE, index
        elif state_override is None and c == "#":
            url.fragment = ""
            return URLParserState.FRAGMENT_STATE, index
        elif not iseof(c):
            if c != "/":
                index -= 1
            return URLParserState.PATH_STATE, index
        elif state_override and url.host is None:
            url.path.append("")  # type: ignore
        return URLParserState.EOF, index - 1  # TBD

    @classmethod
    def _parse_port(
        cls,
        urlstring: str,
        start: int,
        base: Optional[URLRecord],
        url: URLRecord,
        state_override: Optional[URLParserState],
    ) -> Tuple[URLParserState, int]:
        # **port state**
        _ = base
        log = get_logger(cls)
        buffer = ""
        index = start
        for c in cpstream(urlstring[index:]):
            index += 1
            if iscp(c, ASCII_DIGITS):
                buffer += c
            elif (
                (iseof(c) or iscp(c, "/?#"))
                or (url.is_special() and c == "\\")
                or state_override
            ):
                if len(buffer) > 0:
                    port = int(buffer)
                    if port > 0xFFFF:
                        log.error("Port out of range: %d", port)
                        raise URLParseError(f"Port out of range: {port}")
                    if SPECIAL_SCHEMES.get(url.scheme) == port:
                        url.port = None
                    else:
                        url.port = port
                if state_override:
                    return URLParserState.EOF, index - 1
                # return URLParserState.PATH_START_STATE, index - 1
                break
            else:
                log.error("Invalid port in %r", urlstring)
                raise URLParseError(f"Invalid port in {urlstring!r}")
        return URLParserState.PATH_START_STATE, index - 1

    @classmethod
    def _parse_query(
        cls,
        urlstring: str,
        start: int,
        base: Optional[URLRecord],
        url: URLRecord,
        state_override: Optional[URLParserState],
        encoding: str,
    ) -> Tuple[URLParserState, int]:
        # **query state**
        _ = base
        log = get_logger(cls)
        if encoding != "utf-8":
            if url.is_not_special() or url.scheme in ["ws", "wss"]:
                encoding = "utf-8"
        buffer = ""
        query_percent_encode_set = (
            SAFE_SPECIAL_QUERY_PERCENT_ENCODE_SET
            if url.is_special()
            else SAFE_QUERY_PERCENT_ENCODE_SET
        )
        index = start
        for c in cpstream(urlstring[index:]):
            index += 1
            if (state_override is None and c == "#") or iseof(c):
                if len(buffer) == 0 and iseof(c):
                    index -= 1
                    break
                url.query += string_percent_encode(  # type: ignore
                    buffer, query_percent_encode_set, encoding=encoding
                )
                buffer = ""
                if c == "#":
                    url.fragment = ""
                    return URLParserState.FRAGMENT_STATE, index
                if iseof(c):
                    index -= 1
                    break
            elif not iseof(c):
                # TODO: If c is not a URL code point and not U+0025 (%),
                #  validation error.
                if c == "%" and any(
                    x not in ASCII_HEX_DIGITS
                    for x in urlstring[index : index + 2]
                ):
                    log.info(
                        "Found incorrect percent-encoding in %r at position %d",
                        urlstring,
                        index - 1,
                    )
                buffer += c
        return URLParserState.FRAGMENT_STATE, index

    @classmethod
    def _parse_relative(
        cls,
        urlstring: str,
        start: int,
        base: Optional[URLRecord],
        url: URLRecord,
    ) -> Tuple[URLParserState, int]:
        # **relative state**
        log = get_logger(cls)
        assert base and base.scheme != "file"
        url.scheme = base.scheme
        index = start
        c = urlstring[index : index + 1]
        index += 1
        if c == "/":
            return URLParserState.RELATIVE_SLASH_STATE, index
        elif url.is_special() and c == "\\":
            log.info(
                "Expected '/' but got %r in %r at position %d",
                c,
                urlstring,
                index - 1,
            )
            return URLParserState.RELATIVE_SLASH_STATE, index
        url.username = base.username
        url.password = base.password
        url.host = base.host
        url.port = base.port
        url.path = copy.copy(base.path)
        url.query = base.query
        if c == "?":
            url.query = ""
            return URLParserState.QUERY_STATE, index
        elif c == "#":
            url.fragment = ""
            return URLParserState.FRAGMENT_STATE, index
        elif not iseof(c):
            url.query = None
            url.shorten_path()
            return URLParserState.PATH_STATE, index - 1
        return URLParserState.EOF, index - 1  # TBD

    @classmethod
    def _parse_relative_slash(
        cls,
        urlstring: str,
        start: int,
        base: Optional[URLRecord],
        url: URLRecord,
    ) -> Tuple[URLParserState, int]:
        # **relative slash state**
        log = get_logger(cls)
        index = start
        c = urlstring[index : index + 1]
        index += 1
        if url.is_special() and iscp(c, "/\\"):
            if c == "\\":
                log.info(
                    "Expected '/' but got %r in %r at position %d",
                    c,
                    urlstring,
                    index - 1,
                )
            return (
                URLParserState.SPECIAL_AUTHORITY_IGNORE_SLASHES_STATE,
                index,
            )
        elif c == "/":
            return URLParserState.AUTHORITY_STATE, index
        assert base is not None
        url.username = base.username
        url.password = base.password
        url.host = base.host
        url.port = base.port
        return URLParserState.PATH_STATE, index - 1

    @classmethod
    def _parse_scheme(
        cls,
        urlstring: str,
        start: int,
        base: Optional[URLRecord],
        url: URLRecord,
        state_override: Optional[URLParserState],
    ) -> Tuple[URLParserState, int]:
        # **scheme start state**
        log = get_logger(cls)
        index = start
        buffer = ""
        c = urlstring[index : index + 1]
        index += 1
        if iscp(c, ASCII_ALPHA):
            buffer += c
        elif state_override is None:
            return URLParserState.NO_SCHEME_STATE, index - 1
        else:
            log.error("Invalid URL scheme: %r", urlstring)
            raise URLParseError(f"Invalid URL scheme: {urlstring!r}")

        # **scheme state**
        for c in cpstream(urlstring[index:]):
            index += 1
            if iscp(c, ASCII_ALPHANUMERIC) or iscp(c, "+-."):
                buffer += c
            elif c == ":":
                buffer = buffer.lower()
                if state_override:
                    if (
                        (url.is_special() and buffer not in SPECIAL_SCHEMES)
                        or (url.is_not_special() and buffer in SPECIAL_SCHEMES)
                        or (
                            (url.includes_credentials() or url.port)
                            and buffer == "file"
                        )
                        or (
                            url.scheme == "file"
                            and (
                                url.host is None
                                or (
                                    isinstance(url.host, str)
                                    and len(url.host) == 0
                                )
                            )
                        )
                    ):
                        return URLParserState.EOF, index
                url.scheme = buffer
                if state_override:
                    port = url.port
                    if port and SPECIAL_SCHEMES.get(url.scheme) == port:
                        url.port = None
                    return URLParserState.EOF, index
                elif url.scheme == "file":
                    if not urlstring[index:].startswith("//"):
                        log.info(
                            "Expected to start with '//' but got %r in %r "
                            "at position %d",
                            urlstring[index : index + 2],
                            urlstring,
                            index,
                        )
                    return URLParserState.FILE_STATE, index
                elif url.is_special() and base and base.scheme == url.scheme:
                    assert base.is_special()
                    return (
                        URLParserState.SPECIAL_RELATIVE_OR_AUTHORITY_STATE,
                        index,
                    )
                elif url.is_special():
                    return (
                        URLParserState.SPECIAL_AUTHORITY_SLASHES_STATE,
                        index,
                    )
                elif urlstring[index:].startswith("/"):
                    return URLParserState.PATH_OR_AUTHORITY_STATE, index + 1
                else:
                    url.path = ""
                    return URLParserState.OPAQUE_PATH_STATE, index
            elif state_override is None:
                return URLParserState.NO_SCHEME_STATE, start
            else:
                break
        log.error("%r does not end with ':'", urlstring)
        raise URLParseError(f"{urlstring!r} does not end with ':'")

    @classmethod
    def _parse_special_authority_ignore_slashes(
        cls,
        urlstring: str,
        start: int,
        base: Optional[URLRecord],
        url: URLRecord,
    ) -> Tuple[URLParserState, int]:
        # **special authority ignore slashes state**
        _ = base, url
        log = get_logger(cls)
        index = start
        for c in cpstream(urlstring[index:]):
            index += 1
            if not iscp(c, "/\\"):
                # return URLParserState.AUTHORITY_STATE, index - 1
                break
            log.info(
                "Expected neither '/' nor '\\' but got %r in %r at position %d",
                c,
                urlstring,
                index - 1,
            )
        return URLParserState.AUTHORITY_STATE, index - 1

    @classmethod
    def _parse_special_authority_slashes(
        cls,
        urlstring: str,
        start: int,
        base: Optional[URLRecord],
        url: URLRecord,
    ) -> Tuple[URLParserState, int]:
        # **special authority slashes state**
        _ = base, url
        log = get_logger(cls)
        index = start
        c = urlstring[index : index + 1]
        index += 1
        if c == "/" and urlstring[index:].startswith("/"):
            return (
                URLParserState.SPECIAL_AUTHORITY_IGNORE_SLASHES_STATE,
                index + 1,
            )
        log.info(
            "Expected to start with '//' but got %r in %r "
            "at position %d" % (urlstring[start : start + 2], urlstring, start)
        )
        return URLParserState.SPECIAL_AUTHORITY_IGNORE_SLASHES_STATE, index - 1

    @classmethod
    def _parse_special_relative_or_authority(
        cls,
        urlstring: str,
        start: int,
        base: Optional[URLRecord],
        url: URLRecord,
    ) -> Tuple[URLParserState, int]:
        # **special relative or authority state**
        _ = base, url
        log = get_logger(cls)
        index = start
        c = urlstring[index : index + 1]
        index += 1
        if c == "/" and urlstring[index:].startswith("/"):
            return (
                URLParserState.SPECIAL_AUTHORITY_IGNORE_SLASHES_STATE,
                index + 1,
            )
        log.info(
            "Expected to start with '//' but got %r in %r "
            "at position %d" % (urlstring[start : start + 2], urlstring, start)
        )
        return URLParserState.RELATIVE_STATE, index - 1

    @classmethod
    def parse(
        cls,
        urlstring: str,
        base: Optional[URLRecord] = None,
        encoding: str = "utf-8",
        url: Optional[URLRecord] = None,
        state_override: Optional[URLParserState] = None,
    ) -> URLRecord:
        """Parses a string *urlstring* against a base URL *base*.

        Args:
            urlstring: A string to parse.
            base: A base URL.
            encoding: The encoding to encode URL's query.
                If the encoding fails, it will be replaced with the appropriate
                XML character reference.
            url: An input URL record. It will be replaced with the parsing
                result.
            state_override: URLParserState enum.

        Returns:
            If *url* is specified, it will be updated and returned, a new URL
            record will be created otherwise.

        Raises:
            urlstd.error.URLParseError: Raised when URL parsing fails.

        Examples:
            To parse a string as a whole URL:

            >>> url = BasicURLParser.parse('http://example.org/foo/bar')
            >>> str(url)
            'http://example.org/foo/bar'

            To replace a URL's scheme with a string:

            >>> url = BasicURLParser.parse('a://example.net')
            >>> str(url)
            'a://example.net'
            >>> BasicURLParser.parse('B:', url=url,
            ...     state_override=URLParserState.SCHEME_START_STATE)
            >>> str(url)
            'b://example.net'

            To replace a URL's username, password, and host with a string:

            >>> url = BasicURLParser.parse('http://example.org/foo/bar')
            >>> str(url)
            'http://example.org/foo/bar'
            >>> BasicURLParser.parse('user:pass@example.net', url=url,
            ...     state_override=URLParserState.AUTHORITY_STATE)
            >>> str(url)
            'http://user:pass@example.net/foo/bar'

            To replace a URL's host and port with a string:

            >>> url = BasicURLParser.parse(
            ...     'http://user:pass@example.net/foo/bar')
            >>> str(url)
            'http://user:pass@example.net/foo/bar'
            >>> BasicURLParser.parse('0x7F000001:8080', url=url,
            ...     state_override=URLParserState.HOST_STATE)
            >>> str(url)
            'http://user:pass@127.0.0.1:8080/foo/bar'

            To replace a URL's port with a string:

            >>> url = BasicURLParser.parse(
            ...     'http://user:pass@example.net:8080/foo/bar')
            >>> str(url)
            'http://user:pass@example.net:8080/foo/bar'
            >>> BasicURLParser.parse('80', url=url,
            ...     state_override=URLParserState.PORT_STATE)
            >>> str(url)
            'http://user:pass@example.net/foo/bar'

            To replace a URL's path with a string:

            >>> url = BasicURLParser.parse('http://example.org/foo/bar')
            >>> str(url)
            'http://example.org/foo/bar'
            >>> if not url.has_opaque_path():
            ...     url.path = []
            ...     BasicURLParser.parse('?', url=url,
            ...         state_override=URLParserState.PATH_START_STATE)
            >>> str(url)
            'http://example.org/%3F'

            To replace a URL's query with a string:

            >>> url = BasicURLParser.parse(
            ...     'http://example.net/foo/bar?a=1')
            >>> str(url)
            'http://example.net/foo/bar?a=1'
            >>> url.query = ''
            >>> BasicURLParser.parse('baz=2', url=url,
            ...     state_override=URLParserState.QUERY_STATE)
            >>> str(url)
            'http://example.net/foo/bar?baz=2'

            To replace a URL's fragment with a string:

            >>> url = BasicURLParser.parse('http://example.org/foo/bar#nav')
            >>> str(url)
            'http://example.org/foo/bar#nav'
            >>> url.fragment = ''
            >>> BasicURLParser.parse('main', url=url,
            ...     state_override=URLParserState.FRAGMENT_STATE)
            >>> str(url)
            'http://example.org/foo/bar#main'
        """
        log = get_logger(cls)
        if url is None:
            url = URLRecord()
            if LEADING_AND_TRAILING_C0_CONTROL_AND_SPACE_RE.search(urlstring):
                log.info(
                    "Remove any leading and trailing C0 control or space in %r",
                    urlstring,
                )
                urlstring = LEADING_AND_TRAILING_C0_CONTROL_AND_SPACE_RE.sub(
                    "", urlstring
                )

        if ASCII_TAB_OR_NEWLINE_RE.search(urlstring):
            log.info("Remove all ASCII tab or newline in %r", urlstring)
            urlstring = ASCII_TAB_OR_NEWLINE_RE.sub("", urlstring)

        state = state_override or URLParserState.SCHEME_START_STATE
        encoding = encoding.lower()
        if encoding in (UTF8_CODECS | UTF16BE_CODECS | UTF16LE_CODECS):
            encoding = "utf-8"
        index = 0
        while state != URLParserState.EOF:
            prev_state = state
            if state == URLParserState.SCHEME_START_STATE:
                # **scheme start state**
                # **scheme state**
                state, index = cls._parse_scheme(
                    urlstring, index, base, url, state_override
                )
            elif state == URLParserState.NO_SCHEME_STATE:
                # **no scheme state**
                state, index = cls._parse_no_scheme(
                    urlstring, index, base, url
                )
            elif state == URLParserState.SPECIAL_RELATIVE_OR_AUTHORITY_STATE:
                # **special relative or authority state**
                state, index = cls._parse_special_relative_or_authority(
                    urlstring, index, base, url
                )
            elif state == URLParserState.PATH_OR_AUTHORITY_STATE:
                # **path or authority state**
                state, index = cls._parse_path_or_authority(
                    urlstring, index, base, url
                )
            elif state == URLParserState.RELATIVE_STATE:
                # **relative state**
                state, index = cls._parse_relative(urlstring, index, base, url)
            elif state == URLParserState.RELATIVE_SLASH_STATE:
                # **relative slash state**
                state, index = cls._parse_relative_slash(
                    urlstring, index, base, url
                )
            elif state == URLParserState.SPECIAL_AUTHORITY_SLASHES_STATE:
                # **special authority slashes state**
                state, index = cls._parse_special_authority_slashes(
                    urlstring, index, base, url
                )
            elif (
                state == URLParserState.SPECIAL_AUTHORITY_IGNORE_SLASHES_STATE
            ):
                # **special authority ignore slashes state**
                state, index = cls._parse_special_authority_ignore_slashes(
                    urlstring, index, base, url
                )
            elif state == URLParserState.AUTHORITY_STATE:
                # **authority state**
                state, index = cls._parse_authority(
                    urlstring, index, base, url
                )
            elif state in (
                URLParserState.HOST_STATE,
                URLParserState.HOSTNAME_STATE,
            ):
                # **host state**
                # **hostname state**
                state, index = cls._parse_host(
                    urlstring, index, base, url, state_override
                )
            elif state == URLParserState.PORT_STATE:
                # **port state**
                state, index = cls._parse_port(
                    urlstring, index, base, url, state_override
                )
            elif state == URLParserState.FILE_STATE:
                # **file state**
                state, index = cls._parse_file(urlstring, index, base, url)
            elif state == URLParserState.FILE_SLASH_STATE:
                # **file slash state**
                state, index = cls._parse_file_slash(
                    urlstring, index, base, url
                )
            elif state == URLParserState.FILE_HOST_STATE:
                # **file host state**
                state, index = cls._parse_file_host(
                    urlstring, index, base, url, state_override
                )
            elif state == URLParserState.PATH_START_STATE:
                # **path start state**
                state, index = cls._parse_path_start(
                    urlstring, index, base, url, state_override
                )
            elif state == URLParserState.PATH_STATE:
                # **path state**
                state, index = cls._parse_path(
                    urlstring, index, base, url, state_override
                )
            elif state == URLParserState.OPAQUE_PATH_STATE:
                # **opaque path state**
                state, index = cls._parse_opaque_path(
                    urlstring, index, base, url
                )
            elif state == URLParserState.QUERY_STATE:
                # **query state**
                state, index = cls._parse_query(
                    urlstring, index, base, url, state_override, encoding
                )
            elif state == URLParserState.FRAGMENT_STATE:
                # **fragment state**
                state, index = cls._parse_fragment(urlstring, index, base, url)
            else:
                raise NotImplementedError(state)

            log.debug(
                "input=%r, base=%r, state_override=%r, state=%r → %r, "
                "index=%d, url=%r",
                urlstring,
                base,
                state_override,
                prev_state,
                state,
                index,
                url,
            )
        return url


def parse_url(
    urlstring: str,
    base: Optional[str] = None,
    encoding: str = "utf-8",
) -> URLRecord:
    """Parses a string *urlstring* against a base URL *base* using the basic
    URL parser, and returns :class:`.URLRecord`.

    Args:
        urlstring: An absolute-URL or a relative-URL. If *urlstring* is a
            relative-URL, *base* is required.
        base: An absolute-URL for a relative-URL *urlstring*.
        encoding: The encoding to encode URL’s query. If the encoding fails,
            it will be replaced with the appropriate XML character reference.

    Returns:
        A URL record.

    Raises:
        urlstd.error.URLParseError: Raised when URL parsing fails.
    """
    parsed_base = (
        BasicURLParser.parse(base, encoding=encoding) if base else None
    )
    url = BasicURLParser.parse(urlstring, base=parsed_base, encoding=encoding)
    # TODO: Set url’s blob URL entry.
    #  https://url.spec.whatwg.org/#url-parsing
    #  https://w3c.github.io/FileAPI/#blob-url-resolve
    return url
