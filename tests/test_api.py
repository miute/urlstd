import logging
from urllib.parse import ParseResult
from urllib.parse import urlparse as urllib_urlparse

import icupy.icu as icu
import pytest

from urlstd.error import (
    HostParseError,
    IDNAError,
    IPv4AddressParseError,
    IPv6AddressParseError,
    URLParseError,
)
from urlstd.parse import get_logger  # noqa
from urlstd.parse import (
    IDNA,
    BasicURLParser,
    Host,
    Origin,
    URLParserState,
    URLRecord,
    URLSearchParams,
    parse_url,
    urlparse,
)

_MODULE_NAME = parse_url.__module__


def test_get_logger_string(caplog):
    caplog.set_level(logging.DEBUG)
    log = get_logger(__name__)
    log.debug("Hello World!")

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith("tests.test_api")
    assert caplog.record_tuples[-1][1] == logging.DEBUG
    assert caplog.record_tuples[-1][2].startswith("Hello World!")


def test_get_logger_self(caplog):
    class _LoggerTest:
        def test(self):
            _log = get_logger(self)
            _log.debug("Hello World!")

    caplog.set_level(logging.DEBUG)
    test = _LoggerTest()
    test.test()

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith("tests.test_api._LoggerTest")
    assert caplog.record_tuples[-1][1] == logging.DEBUG
    assert caplog.record_tuples[-1][2].startswith("Hello World!")


def test_host_parse_ascii_domain_01(caplog):
    """Contains a forbidden host code point in ASCII-domain."""
    caplog.set_level(logging.INFO)
    with pytest.raises(HostParseError) as exc_info:
        _ = Host.parse("a<b")
    assert exc_info.value.args[0].startswith(
        "Contains a forbidden host code point in ASCII-domain"
    )

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.ERROR
    assert caplog.record_tuples[-1][2].startswith(
        "Contains a forbidden host code point in ASCII-domain"
    )


def test_host_parse_ascii_domain_02(caplog):
    """Invalid domain name."""
    caplog.set_level(logging.INFO)
    with pytest.raises(HostParseError) as exc_info:
        _ = Host.parse("xn--")
    assert exc_info.value.args[0].startswith("Invalid domain name")

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.ERROR
    assert caplog.record_tuples[-1][2].startswith("Invalid domain name")


def test_host_parse_ascii_domain_03(caplog):
    """Empty host after the domain to ASCII."""
    caplog.set_level(logging.INFO)
    with pytest.raises(HostParseError) as exc_info:
        _ = Host.parse("\u00ad")
    assert exc_info.value.args[0].startswith(
        "Empty host after the domain to ASCII"
    )

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.ERROR
    assert caplog.record_tuples[-1][2].startswith(
        "Empty host after the domain to ASCII"
    )


def test_host_parse_ascii_domain_04(caplog):
    """Contains a forbidden host code point in ASCII-domain."""
    caplog.set_level(logging.INFO)
    with pytest.raises(HostParseError) as exc_info:
        _ = Host.parse("ho%00st")
    assert exc_info.value.args[0].startswith(
        "Contains a forbidden host code point in ASCII-domain"
    )

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.ERROR
    assert caplog.record_tuples[-1][2].startswith(
        "Contains a forbidden host code point in ASCII-domain"
    )


def test_host_parse_ipv4_01(caplog):
    """Invalid IPv4 address."""
    caplog.set_level(logging.INFO)
    with pytest.raises(IPv4AddressParseError) as exc_info:
        _ = Host.parse("1.2.3.4.5")
    assert exc_info.value.args[0].endswith(
        "does not appear to be an IPv4 address"
    )

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.ERROR
    assert caplog.record_tuples[-1][2].endswith(
        "does not appear to be an IPv4 address"
    )


def test_host_parse_ipv4_02(caplog):
    """Invalid IPv4 address."""
    caplog.set_level(logging.INFO)
    with pytest.raises(IPv4AddressParseError) as exc_info:
        _ = Host.parse("1.2.3.08")
    assert exc_info.value.args[0].endswith(
        "does not appear to be an IPv4 address"
    )

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.ERROR
    assert caplog.record_tuples[-1][2].endswith(
        "does not appear to be an IPv4 address"
    )


def test_host_parse_ipv4_03(caplog):
    """Any but the last part of IPv4 address are greater than 255."""
    caplog.set_level(logging.INFO)
    with pytest.raises(IPv4AddressParseError) as exc_info:
        _ = Host.parse("0x100.0.0.1")
    assert exc_info.value.args[0].startswith(
        "Any but the last part of IPv4 address are greater than 255"
    )

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.ERROR
    assert caplog.record_tuples[-1][2].startswith(
        "Any but the last part of IPv4 address are greater than 255"
    )


def test_host_parse_ipv4_04(caplog):
    """The last part of IPv4 address is greater than or equal to 256"""
    caplog.set_level(logging.INFO)
    with pytest.raises(IPv4AddressParseError) as exc_info:
        _ = Host.parse("192.168.0.0x100")
    assert exc_info.value.args[0].startswith(
        "The last part of IPv4 address is greater than or equal to"
    )

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.ERROR
    assert caplog.record_tuples[-1][2].startswith(
        "The last part of IPv4 address is greater than or equal to"
    )


def test_host_parse_ipv6_01(caplog):
    """Invalid IPv6 address: Unexpected end of input."""
    caplog.set_level(logging.INFO)
    with pytest.raises(IPv6AddressParseError) as exc_info:
        _ = Host.parse("[1::")
    assert exc_info.value.args[0].startswith("Unexpected end of input")

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.ERROR
    assert caplog.record_tuples[-1][2].startswith(
        "Invalid IPv6 address: Unexpected end of input"
    )


def test_host_parse_ipv6_02(caplog):
    """Invalid IPv6 address."""
    caplog.set_level(logging.INFO)
    with pytest.raises(IPv6AddressParseError) as exc_info:
        _ = Host.parse("[0:1:2:3:4:5:6:7:8]")
    assert exc_info.value.args[0].startswith(
        "Exactly 8 parts expected without"
    )

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.ERROR
    assert caplog.record_tuples[-1][2].startswith(
        "Invalid IPv6 address: Exactly 8 parts expected without"
    )


def test_host_parse_opaque_host_01(caplog):
    """Contains a forbidden host code point excluding '%'"""
    caplog.set_level(logging.INFO)
    with pytest.raises(HostParseError) as exc_info:
        _ = Host.parse("a<b", True)
    assert exc_info.value.args[0].startswith(
        "Contains a forbidden host code point excluding '%'"
    )

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.ERROR
    assert caplog.record_tuples[-1][2].startswith(
        "Contains a forbidden host code point excluding '%'"
    )


def test_host_parse_opaque_host_02(caplog):
    """Incorrect percent-encoding."""
    caplog.set_level(logging.INFO)
    _ = Host.parse("%zz%66%a.com", True)

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.INFO
    assert caplog.record_tuples[-1][2].startswith(
        "Found incorrect percent-encoding in"
    )


def test_idna_domain_to_ascii_errors_string():
    errors = IDNA._errors_to_string(0x80003)
    assert (
        errors == "UIDNA_ERROR_EMPTY_LABEL|UIDNA_ERROR_LABEL_TOO_LONG|0x80000"
    )


def test_idna_domain_to_ascii_exceptions(caplog, mocker):
    caplog.set_level(logging.INFO)
    mocker.patch(
        "icupy.icu.IDNA.name_to_ascii",
        side_effect=icu.ICUError(icu.ErrorCode()),
    )

    with pytest.raises(IDNAError):
        _ = IDNA.domain_to_ascii("www.eXample.cOm")

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.ERROR
    assert caplog.record_tuples[-1][2].startswith(
        "Unable to convert domain name"
    )


def test_idna_domain_to_ascii_use_std3_rules(caplog):
    """Domain contains non-LDH ASCII."""
    caplog.set_level(logging.INFO)
    domain = "a\u2260b\u226Ec\u226Fd"

    assert IDNA.domain_to_ascii(domain) == "xn--abcd-5n9aqdi"
    assert len(caplog.record_tuples) == 0

    assert IDNA.domain_to_ascii(domain, False) == "xn--abcd-5n9aqdi"
    assert len(caplog.record_tuples) == 0

    with pytest.raises(HostParseError):
        _ = IDNA.domain_to_ascii(domain, True)
    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.ERROR
    assert caplog.record_tuples[-1][2].startswith("Invalid domain name")


def test_parse_url_basic():
    """parse_url()"""
    urlstring = "/some/path?b#c"
    base = "http://user:pass@example.org:21/foo/bar;par"
    url = parse_url(urlstring, base)
    assert isinstance(url, URLRecord)
    assert url.href == "http://user:pass@example.org:21/some/path?b#c"
    assert url.scheme == "http"
    assert url.username == "user"
    assert url.password == "pass"
    assert url.host == "example.org"
    assert url.port == 21
    assert isinstance(url.path, list)
    assert url.path == ["some", "path"]
    assert url.query == "b"
    assert url.fragment == "c"
    assert str(url) == "http://user:pass@example.org:21/some/path?b#c"
    assert not url.cannot_have_username_password_port()
    assert not url.has_opaque_path()
    assert url.includes_credentials()
    assert not url.is_not_special()
    assert url.is_special()
    origin = url.origin
    assert isinstance(origin, Origin)
    assert origin.scheme == "http"
    assert origin.host == "example.org"
    assert origin.port == 21
    assert origin.domain is None
    assert str(origin) == "http://example.org:21"
    assert url.serialize_path() == "/some/path"
    assert url.serialize_url() == url.href == str(url)

    urlstring = "javascript:example.com/"
    base = "about:blank"
    url = parse_url(urlstring, base)
    assert isinstance(url, URLRecord)
    assert url.href == "javascript:example.com/"
    assert url.scheme == "javascript"
    assert len(url.username) == 0
    assert len(url.password) == 0
    assert url.host is None
    assert url.port is None
    assert isinstance(url.path, str)
    assert url.path == "example.com/"
    assert url.query is None
    assert url.fragment is None
    assert str(url) == "javascript:example.com/"
    assert url.cannot_have_username_password_port()
    assert url.has_opaque_path()
    assert not url.includes_credentials()
    assert url.is_not_special()
    assert not url.is_special()
    assert url.origin is None
    assert url.serialize_path() == "example.com/"
    assert url.serialize_url() == url.href == str(url)


def test_parse_url_with_encoding():
    """parse_url() with encoding."""
    urlstring = "http://example.org/test?ÿ"
    base = "http://example.org/foo/bar"

    url = parse_url(urlstring, base)  # encoding="utf-8"
    assert isinstance(url, URLRecord)
    assert url.href == "http://example.org/test?%C3%BF"
    assert url.query == "%C3%BF"

    url = parse_url(urlstring, base, encoding="utf-8")
    assert isinstance(url, URLRecord)
    assert url.href == "http://example.org/test?%C3%BF"
    assert url.query == "%C3%BF"

    # utf16* -> utf-8
    url = parse_url(urlstring, base, encoding="utf-16be")
    assert isinstance(url, URLRecord)
    assert url.href == "http://example.org/test?%C3%BF"
    assert url.query == "%C3%BF"

    url = parse_url(urlstring, base, encoding="windows-1251")
    assert isinstance(url, URLRecord)
    assert url.href == "http://example.org/test?%26%23255%3B"
    assert url.query == "%26%23255%3B"

    url = parse_url(urlstring, base, encoding="windows-1252")
    assert isinstance(url, URLRecord)
    assert url.href == "http://example.org/test?%FF"
    assert url.query == "%FF"


def test_parse_url_with_encoding_ws():
    """parse_url() with encoding (ws/wss protocol)."""
    urlstring = "ws://example.org/test?ÿ"
    base = "http://example.org/foo/bar"

    url = parse_url(urlstring, base)  # encoding="utf-8"
    assert isinstance(url, URLRecord)
    assert url.href == "ws://example.org/test?%C3%BF"
    assert url.query == "%C3%BF"

    url = parse_url(urlstring, base, encoding="utf-8")
    assert isinstance(url, URLRecord)
    assert url.href == "ws://example.org/test?%C3%BF"
    assert url.query == "%C3%BF"

    url = parse_url(urlstring, base, encoding="windows-1251")  # -> utf-8
    assert isinstance(url, URLRecord)
    assert url.href == "ws://example.org/test?%C3%BF"
    assert url.query == "%C3%BF"

    urlstring = "wss://example.org/test?ÿ"

    url = parse_url(urlstring, base)  # encoding="utf-8"
    assert isinstance(url, URLRecord)
    assert url.href == "wss://example.org/test?%C3%BF"
    assert url.query == "%C3%BF"

    url = parse_url(urlstring, base, encoding="utf-8")
    assert isinstance(url, URLRecord)
    assert url.href == "wss://example.org/test?%C3%BF"
    assert url.query == "%C3%BF"

    url = parse_url(urlstring, base, encoding="windows-1251")  # -> utf-8
    assert isinstance(url, URLRecord)
    assert url.href == "wss://example.org/test?%C3%BF"
    assert url.query == "%C3%BF"


def test_parse_url_authority_state_01(caplog):
    """Validation error in authority state."""
    caplog.set_level(logging.INFO)
    urlstring = "https://@test@test@example:800/"
    base = "http://doesnotmatter/"
    _ = parse_url(urlstring, base)

    assert len(caplog.record_tuples) >= 3
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.INFO
    assert caplog.record_tuples[-1][2].startswith("Found '@' in")
    assert caplog.record_tuples[-1][2].endswith("at position 18")


def test_parse_url_authority_state_02(caplog):
    """Parse error in authority state."""
    caplog.set_level(logging.INFO)
    urlstring = "http://user:pass@/"
    base = "about:blank"
    with pytest.raises(URLParseError) as exc_info:
        _ = parse_url(urlstring, base)
    assert exc_info.value.args[0].startswith("Invalid username or password")

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.ERROR
    assert caplog.record_tuples[-1][2].startswith(
        "Invalid username or password"
    )


def test_parse_url_file_state_01(caplog):
    """Validation error in file state."""
    caplog.set_level(logging.INFO)
    urlstring = "file:\\c:"
    base = "about:blank"
    _ = parse_url(urlstring, base)

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.INFO
    assert caplog.record_tuples[-1][2].startswith(
        "Expected '/' but got '\\\\' in"
    )
    assert caplog.record_tuples[-1][2].endswith("at position 5")


def test_parse_url_file_state_02(caplog):
    """Validation error in file state."""
    caplog.set_level(logging.INFO)
    urlstring = "file:c://foo/bar.html"
    base = "file:///tmp/mock/path"
    _ = parse_url(urlstring, base)

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.INFO
    assert caplog.record_tuples[-1][2].startswith(
        "Unexpected Windows drive letter in"
    )
    assert caplog.record_tuples[-1][2].endswith("at position 5")


def test_parse_url_file_host_state(caplog):
    """Validation error in file host state."""
    caplog.set_level(logging.INFO)
    urlstring = "file://c://foo/bar"
    base = "file:///c:/baz/qux"
    _ = parse_url(urlstring, base)

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.INFO
    assert caplog.record_tuples[-1][2].startswith(
        "Unexpected Windows drive letter in"
    )
    assert caplog.record_tuples[-1][2].endswith("at position 7")


def test_parse_url_file_slash_state(caplog):
    """Validation error in file slash state."""
    caplog.set_level(logging.INFO)
    urlstring = "file:\\\\//"
    base = "about:blank"
    _ = parse_url(urlstring, base)

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.INFO
    assert caplog.record_tuples[-1][2].startswith(
        "Expected '/' but got '\\\\' in"
    )
    assert caplog.record_tuples[-1][2].endswith("at position 6")


def test_parse_url_fragment_state(caplog):
    """Validation error in fragment state."""
    caplog.set_level(logging.INFO)
    urlstring = "http://example.org/test?a#%GH"
    base = "about:blank"
    _ = parse_url(urlstring, base)

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.INFO
    assert caplog.record_tuples[-1][2].startswith(
        "Found incorrect percent-encoding in"
    )
    assert caplog.record_tuples[-1][2].endswith("at position 26")


def test_parse_url_host_state_01(caplog):
    """Parse error in host state or hostname state."""
    caplog.set_level(logging.INFO)
    urlstring = "sc://:/"
    base = "about:blank"
    with pytest.raises(URLParseError) as exc_info:
        _ = parse_url(urlstring, base)
    assert exc_info.value.args[0].startswith("Unexpected empty host in")

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.ERROR
    assert caplog.record_tuples[-1][2].startswith("Unexpected empty host in")


def test_parse_url_host_state_02(caplog):
    """Parse error in host state or hostname state. (special scheme)"""
    caplog.set_level(logging.INFO)
    urlstring = "http://"
    base = "about:blank"
    with pytest.raises(URLParseError) as exc_info:
        _ = parse_url(urlstring, base)
    assert exc_info.value.args[0].startswith("Unexpected empty host in")

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.ERROR
    assert caplog.record_tuples[-1][2].startswith("Unexpected empty host in")


def test_parse_url_no_scheme_state(caplog):
    """Parse error in no scheme state."""
    caplog.set_level(logging.INFO)
    urlstring = "////c:/"
    base = None
    with pytest.raises(URLParseError) as exc_info:
        _ = parse_url(urlstring, base)
    assert exc_info.value.args[0].startswith("URL scheme not found in")

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.ERROR
    assert caplog.record_tuples[-1][2].startswith("URL scheme not found in")


def test_parse_url_opaque_path_state(caplog):
    """Validation error in opaque path state."""
    caplog.set_level(logging.INFO)
    urlstring = "sc:\\../%GH"
    base = "about:blank"
    _ = parse_url(urlstring, base)

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.INFO
    assert caplog.record_tuples[-1][2].startswith(
        "Found incorrect percent-encoding in"
    )
    assert caplog.record_tuples[-1][2].endswith("at position 7")


def test_parse_url_path_state_01(caplog):
    """Validation error in path state."""
    caplog.set_level(logging.INFO)
    urlstring = "http://foo.com/\\@"
    base = "http://example.org/foo/bar"
    _ = parse_url(urlstring, base)

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.INFO
    assert caplog.record_tuples[-1][2].startswith(
        "Expected '/' but got '\\\\' in"
    )
    assert caplog.record_tuples[-1][2].endswith("at position 15")


def test_parse_url_path_state_02(caplog):
    """Validation error in path state."""
    caplog.set_level(logging.INFO)
    urlstring = "http://foo.com/%GH"
    base = "http://example.org/foo/bar"
    _ = parse_url(urlstring, base)

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.INFO
    assert caplog.record_tuples[-1][2].startswith(
        "Found incorrect percent-encoding in"
    )
    assert caplog.record_tuples[-1][2].endswith("at position 15")


def test_parse_url_path_start_state(caplog):
    """Validation error in path start state."""
    caplog.set_level(logging.INFO)
    urlstring = "\\\\server\\file"
    base = "file:///tmp/mock/path"
    _ = parse_url(urlstring, base)

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.INFO
    assert caplog.record_tuples[-1][2].startswith(
        "Expected '/' but got '\\\\' in"
    )
    assert caplog.record_tuples[-1][2].endswith("at position 8")


def test_parse_url_port_state_01(caplog):
    """Parse error in port state."""
    caplog.set_level(logging.INFO)
    urlstring = "http://f:999999/c"
    base = "about:blank"
    with pytest.raises(URLParseError) as exc_info:
        _ = parse_url(urlstring, base)
    assert exc_info.value.args[0].startswith("Port out of range")

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.ERROR
    assert caplog.record_tuples[-1][2].startswith("Port out of range")


def test_parse_url_port_state_02(caplog):
    """Parse error in port state."""
    caplog.set_level(logging.INFO)
    urlstring = "http://foo:-80/"
    base = "about:blank"
    with pytest.raises(URLParseError) as exc_info:
        _ = parse_url(urlstring, base)
    assert exc_info.value.args[0].startswith("Invalid port")

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.ERROR
    assert caplog.record_tuples[-1][2].startswith("Invalid port")


def test_parse_url_query_state(caplog):
    """Validation error in query state."""
    caplog.set_level(logging.INFO)
    urlstring = "http://example.org/test?%GH"
    base = "about:blank"
    _ = parse_url(urlstring, base)

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.INFO
    assert caplog.record_tuples[-1][2].startswith(
        "Found incorrect percent-encoding in"
    )
    assert caplog.record_tuples[-1][2].endswith("at position 24")


def test_parse_url_relative_state(caplog):
    """Validation error in relative state."""
    caplog.set_level(logging.INFO)
    urlstring = "\\x"
    base = "http://example.org/foo/bar"
    _ = parse_url(urlstring, base)

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.INFO
    assert caplog.record_tuples[-1][2].startswith(
        "Expected '/' but got '\\\\' in"
    )
    assert caplog.record_tuples[-1][2].endswith("at position 0")


def test_parse_url_relative_slash_state(caplog):
    """Validation error in relative slash state."""
    caplog.set_level(logging.INFO)
    urlstring = "/\\server/file"
    base = "http://example.org/foo/bar"
    _ = parse_url(urlstring, base)

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.INFO
    assert caplog.record_tuples[-1][2].startswith(
        "Expected '/' but got '\\\\' in"
    )
    assert caplog.record_tuples[-1][2].endswith("at position 1")


def test_parse_url_scheme_start_state(caplog):
    """Parse error in scheme start state."""
    caplog.set_level(logging.INFO)
    urlstring = "\u00ad:"
    base = None
    with pytest.raises(URLParseError) as exc_info:
        _ = BasicURLParser.parse(
            urlstring,
            base=base,
            state_override=URLParserState.SCHEME_START_STATE,
        )
    assert exc_info.value.args[0].startswith("Invalid URL scheme")

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.ERROR
    assert caplog.record_tuples[-1][2].startswith("Invalid URL scheme")


def test_parse_url_scheme_state_01(caplog):
    """Validation error in scheme state."""
    caplog.set_level(logging.INFO)
    urlstring = "file:\\c:\\foo\\bar"
    base = "about:blank"
    _ = parse_url(urlstring, base)

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[0][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[0][1] == logging.INFO
    assert caplog.record_tuples[0][2].startswith(
        "Expected to start with '//' but got '\\\\c'"
    )
    assert caplog.record_tuples[0][2].endswith("at position 5")


def test_parse_url_scheme_state_02(caplog):
    """Parse error in scheme state."""
    caplog.set_level(logging.INFO)
    urlstring = "http"
    with pytest.raises(URLParseError) as exc_info:
        _ = BasicURLParser.parse(
            urlstring,
            state_override=URLParserState.SCHEME_START_STATE,
        )
    assert exc_info.value.args[0].endswith("does not end with ':'")

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.ERROR
    assert caplog.record_tuples[-1][2].endswith("does not end with ':'")


def test_parse_url_special_authority_ignore_slashes_state(caplog):
    """Validation error in special authority ignore slashes state."""
    caplog.set_level(logging.INFO)
    urlstring = "///x/"
    base = "http://example.org/"
    _ = parse_url(urlstring, base)

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[0][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[0][1] == logging.INFO
    assert caplog.record_tuples[0][2].startswith(
        "Expected neither '/' nor '\\' but got '/'"
    )
    assert caplog.record_tuples[0][2].endswith("at position 2")


def test_parse_url_special_authority_slashes_state(caplog):
    """Validation error in special authority slashes state."""
    caplog.set_level(logging.INFO)
    urlstring = "http:\\x"
    base = None
    _ = parse_url(urlstring, base)

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[0][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[0][1] == logging.INFO
    assert caplog.record_tuples[0][2].startswith(
        "Expected to start with '//' but got '\\\\x'"
    )
    assert caplog.record_tuples[0][2].endswith("at position 5")


def test_parse_url_special_relative_or_authority_state(caplog):
    """Validation error in special relative or authority state."""
    caplog.set_level(logging.INFO)
    urlstring = "http:\\x"
    base = "http://example.org/"
    _ = parse_url(urlstring, base)

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[0][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[0][1] == logging.INFO
    assert caplog.record_tuples[0][2].startswith(
        "Expected to start with '//' but got '\\\\x'"
    )
    assert caplog.record_tuples[0][2].endswith("at position 5")


@pytest.mark.parametrize(
    "urlstring",
    [
        "http://user:pass@foo:21/bar/baz;par1;par2?b#c",
        "http://user:pass@foo:21/bar/baz;par1;par2?b",
        "http://user:pass@foo:21/bar/baz;par1;par2#c",
        "http://user:pass@foo:21/bar/baz#c",
        "http://user:pass@foo:21/#c",
        # "http://user:@foo:21/bar/baz;par1;par2?b#c",
        # -> "http://user@foo:21/bar/baz;par1;par2?b#c"
        "http://user@foo:21/bar/baz;par1;par2?b#c",
        "http://foo/bar/baz?b#c",
        "http://foo/",
        # "http://foo", -> "http://foo/"
    ],
)
def test_urlparse_basic(urlstring):
    """urlparse()"""
    result1 = urlparse(urlstring)
    result2 = urllib_urlparse(urlstring)
    assert isinstance(result1, ParseResult)
    assert result1 == result2

    result1 = urlparse(urlstring, allow_fragments=False)
    result2 = urllib_urlparse(urlstring, allow_fragments=False)
    assert isinstance(result1, ParseResult)
    assert result1 == result2


def test_urlparse_with_encoding():
    """urlparse() with encoding."""
    urlstring = "/some/path"
    base = "http://user@example.org/smth"
    result = urlparse(urlstring, base)
    assert result == ("http", "user@example.org", "/some/path", "", "", "")

    urlstring = "http://example.org/test?yÿ"
    result = urlparse(urlstring, encoding="utf-8")
    assert result == ("http", "example.org", "/test", "", "y%C3%BF", "")

    result = urlparse(urlstring, encoding="windows-1251")
    assert result == ("http", "example.org", "/test", "", "y%26%23255%3B", "")

    result = urlparse(urlstring, encoding="windows-1252")
    assert result == ("http", "example.org", "/test", "", "y%FF", "")


def test_urlsearchparams_add():
    params = URLSearchParams("a=1&b=2&a=3&c=4")
    with pytest.raises(TypeError):
        params += 1  # type: ignore


def test_urlsearchparams_collections_abc():
    """class URLSearchParams(collections.abc.Collection)"""
    params = URLSearchParams("a=1&b=2&a=3&c=4")

    assert len(params) == 4
    assert list(iter(params)) == [
        ("a", "1"),
        ("b", "2"),
        ("a", "3"),
        ("c", "4"),
    ]
    assert "a" in params
    assert "d" not in params
    with pytest.raises(TypeError):
        _ = 1 in params
    assert list(params.keys()) == ["a", "b", "a", "c"]
    assert list(params.values()) == ["1", "2", "3", "4"]
    assert list(params.entries()) == [
        ("a", "1"),
        ("b", "2"),
        ("a", "3"),
        ("c", "4"),
    ]

    params = URLSearchParams()
    assert len(params) == 0
    assert list(iter(params)) == []
    assert "a" not in params
    assert "d" not in params
    with pytest.raises(TypeError):
        _ = 1 in params
    assert len(list(params.keys())) == 0
    assert len(list(params.values())) == 0
    assert len(list(params.entries())) == 0


def test_urlsearchparams_construct_raise_exception():
    with pytest.raises(TypeError):
        _ = URLSearchParams(1)  # type: ignore  # noqa

    with pytest.raises(TypeError):
        _ = URLSearchParams("a", "1")  # type: ignore  # noqa


def test_urlsearchparams_construct_with_surrogates():
    """URLSearchParams construct with 3 unpaired surrogates (no leading)"""
    params = URLSearchParams(
        [["x\uDC53", "1"], ["x\uDC53", 2], ["x\uDC53", 3.0]]
    )
    assert len(params) == 3
    assert params.get("x\uDC53") == "1"
    assert params.get("x\uFFFD") == "1"
    assert params.get_all("x\uDC53") == ("1", "2", "3.0")
    assert params.get_all("x\uFFFD") == ("1", "2", "3.0")

    params.delete("x\uFFFD")
    assert len(params) == 0
