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
    IPv4Address,
    Origin,
    URLParserState,
    URLRecord,
    URLSearchParams,
    is_url_code_points,
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
    """Contains a forbidden domain code point in ASCII-domain."""
    caplog.set_level(logging.INFO)

    host = "a<b"
    with pytest.raises(HostParseError) as exc_info:
        _ = Host.parse(host)
    assert exc_info.value.args[0] == (
        f"input's host contains a forbidden domain code point: {host!r}"
    )

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.ERROR
    assert caplog.record_tuples[-1][2] == (
        "domain-invalid-code-point: "
        f"input's host contains a forbidden domain code point: {host!r}"
    )


def test_host_parse_ascii_domain_02(caplog):
    """Invalid domain name."""
    caplog.set_level(logging.INFO)

    host = "xn--"
    with pytest.raises(HostParseError) as exc_info:
        _ = Host.parse(host)
    assert exc_info.value.args[0] == (
        "Unicode ToASCII records an error: "
        f"domain={host!r} errors=UIDNA_ERROR_INVALID_ACE_LABEL (0x0400)"
    )

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.ERROR
    assert caplog.record_tuples[-1][2] == (
        "domain-to-ASCII: "
        "Unicode ToASCII records an error: "
        f"domain={host!r} errors=UIDNA_ERROR_INVALID_ACE_LABEL (0x0400)"
    )


def test_host_parse_ascii_domain_03(caplog):
    """Empty host after the domain to ASCII."""
    caplog.set_level(logging.INFO)

    host = "\u00ad"
    with pytest.raises(HostParseError) as exc_info:
        _ = Host.parse(host)
    assert exc_info.value.args[0] == (
        f"Unicode ToASCII returns the empty string: {host!r}"
    )

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.ERROR
    assert caplog.record_tuples[-1][2] == (
        "domain-to-ASCII: "
        f"Unicode ToASCII returns the empty string: {host!r}"
    )


def test_host_parse_ascii_domain_04(caplog):
    """Contains a forbidden host code point in ASCII-domain."""
    caplog.set_level(logging.INFO)

    host = "ho%00st"
    with pytest.raises(HostParseError) as exc_info:
        _ = Host.parse(host)
    host = "ho\x00st"
    assert exc_info.value.args[0] == (
        f"input's host contains a forbidden domain code point: {host!r}"
    )

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.ERROR
    assert caplog.record_tuples[-1][2] == (
        "domain-invalid-code-point: "
        f"input's host contains a forbidden domain code point: {host!r}"
    )


def test_host_parse_ipv4_basic(caplog):
    """IPv4 tests."""
    address = Host.parse("192.168.0.1")
    assert isinstance(address, int)
    assert address == 0xC0A80001
    assert Host.serialize(address) == "192.168.0.1"

    address = Host.parse("3232235521")
    assert isinstance(address, int)
    assert address == 0xC0A80001
    assert Host.serialize(address) == "192.168.0.1"

    address = Host.parse("030052000001")
    assert isinstance(address, int)
    assert address == 0xC0A80001
    assert Host.serialize(address) == "192.168.0.1"

    address = Host.parse("0xC0A80001")
    assert isinstance(address, int)
    assert address == 0xC0A80001
    assert Host.serialize(address) == "192.168.0.1"

    address = Host.parse("0xc0a80001")
    assert isinstance(address, int)
    assert address == 0xC0A80001
    assert Host.serialize(address) == "192.168.0.1"

    address = Host.parse("192.0250.0.1")
    assert isinstance(address, int)
    assert address == 0xC0A80001
    assert Host.serialize(address) == "192.168.0.1"

    address = Host.parse("0xC0.168.0.1")
    assert isinstance(address, int)
    assert address == 0xC0A80001
    assert Host.serialize(address) == "192.168.0.1"

    assert IPv4Address.is_ends_in_a_number("") is False
    assert IPv4Address.is_ends_in_a_number("192.168.0.1") is True
    assert IPv4Address.is_ends_in_a_number("3232235521") is True
    assert IPv4Address.is_ends_in_a_number("030052000001") is True
    assert IPv4Address.is_ends_in_a_number("0xC0A80001") is True
    assert IPv4Address.is_ends_in_a_number("192.168.x.0250") is True
    assert IPv4Address.is_ends_in_a_number("192.168.x.0xC0") is True
    assert IPv4Address.is_ends_in_a_number("08") is True
    assert IPv4Address.is_ends_in_a_number("C0") is False
    assert IPv4Address.is_ends_in_a_number("0xGH") is False


def test_host_parse_ipv4_01(caplog):
    """Invalid IPv4 address: IPv4-too-many-parts."""
    caplog.set_level(logging.INFO)

    host = "1.2.3.4.5"
    with pytest.raises(IPv4AddressParseError) as exc_info:
        _ = Host.parse(host)
    assert exc_info.value.args[0] == (
        f"IPv4 address does not consist of exactly 4 parts: {host!r}"
    )

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.ERROR
    assert caplog.record_tuples[-1][2] == (
        "IPv4-too-many-parts: "
        f"IPv4 address does not consist of exactly 4 parts: {host!r}"
    )


def test_host_parse_ipv4_02(caplog):
    """Invalid IPv4 address: IPv4-non-numeric-part."""
    caplog.set_level(logging.INFO)

    host = "1.2.3.08"
    with pytest.raises(IPv4AddressParseError) as exc_info:
        _ = Host.parse(host)
    assert exc_info.value.args[0] == (
        f"IPv4 address part is not numeric: '08' in {host!r}"
    )

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.ERROR
    assert caplog.record_tuples[-1][2] == (
        "IPv4-non-numeric-part: "
        f"IPv4 address part is not numeric: '08' in {host!r}"
    )


def test_host_parse_ipv4_03(caplog):
    """Invalid IPv4 address: Any but the last part of the IPv4 address is
    greater than 255.
    """
    caplog.set_level(logging.INFO)

    host = "0x100.0.0.1"
    with pytest.raises(IPv4AddressParseError) as exc_info:
        _ = Host.parse(host)
    assert exc_info.value.args[0] == (
        "any part but the last part of the IPv4 address is greater than 255: "
        f"{host!r} ([256, 0, 0, 1])"
    )

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.ERROR
    assert caplog.record_tuples[-1][2] == (
        "any part but the last part of the IPv4 address is greater than 255: "
        f"{host!r} ([256, 0, 0, 1])"
    )


def test_host_parse_ipv4_04(caplog):
    """Invalid IPv4 address: The last part of the IPv4 address is greater than
    or equal to 256.
    """
    caplog.set_level(logging.INFO)

    host = "192.168.0.0x100"
    with pytest.raises(IPv4AddressParseError) as exc_info:
        _ = Host.parse(host)
    assert exc_info.value.args[0] == (
        "last part of the IPv4 address is greater than or equal to 256: "
        f"{host!r} ([192, 168, 0, 256])"
    )

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.ERROR
    assert caplog.record_tuples[-1][2] == (
        "last part of the IPv4 address is greater than or equal to 256: "
        f"{host!r} ([192, 168, 0, 256])"
    )


def test_host_parse_ipv4_05(caplog):
    """IPv4 tests: IPv4-empty-part."""
    caplog.set_level(logging.INFO)

    host = "127.0.0.1."
    address = Host.parse(host)
    assert isinstance(address, int)

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.INFO
    assert caplog.record_tuples[-1][2] == (
        f"IPv4-empty-part: IPv4 address ends with a U+002E (.): {host!r}"
    )

    assert Host.serialize(address) == "127.0.0.1"


def test_host_parse_ipv4_06a(caplog):
    """IPv4 tests: IPv4-non-decimal-part."""
    caplog.set_level(logging.INFO)

    host = "0xC0.168.1"
    address = Host.parse(host)
    assert isinstance(address, int)

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.INFO
    assert caplog.record_tuples[-1][2] == (
        "IPv4-non-decimal-part: "
        "IPv4 address contains numbers expressed using hexadecimal or octal digits: "
        f"'0xc0' in {host.lower()!r}"
    )

    assert Host.serialize(address) == "192.168.0.1"


def test_host_parse_ipv4_06b(caplog):
    """IPv4 tests: IPv4-non-decimal-part."""
    caplog.set_level(logging.INFO)

    host = "192.0250.1"
    address = Host.parse(host)
    assert isinstance(address, int)

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.INFO
    assert caplog.record_tuples[-1][2] == (
        "IPv4-non-decimal-part: "
        "IPv4 address contains numbers expressed using hexadecimal or octal digits: "
        f"'0250' in {host!r}"
    )

    assert Host.serialize(address) == "192.168.0.1"


def test_host_parse_ipv6_basic(caplog):
    """IPv6 tests."""
    address = Host.parse("[::]")
    assert isinstance(address, tuple)
    assert len(address) == 8
    assert Host.serialize(address) == "[::]"

    address = Host.parse("[1:0::]")
    assert isinstance(address, tuple)
    assert len(address) == 8
    assert Host.serialize(address) == "[1::]"

    address = Host.parse("[1:2:0:0:5:0:0:0]")
    assert isinstance(address, tuple)
    assert len(address) == 8
    assert Host.serialize(address) == "[1:2:0:0:5::]"

    address = Host.parse("[1:2:0:0:0:0:0:3]")
    assert isinstance(address, tuple)
    assert len(address) == 8
    assert Host.serialize(address) == "[1:2::3]"

    address = Host.parse("[1:2::3]")
    assert isinstance(address, tuple)
    assert len(address) == 8
    assert Host.serialize(address) == "[1:2::3]"

    address = Host.parse("[0:1:0:1:0:1:0:1]")
    assert isinstance(address, tuple)
    assert len(address) == 8
    assert Host.serialize(address) == "[0:1:0:1:0:1:0:1]"

    address = Host.parse("[1:0:1:0:1:0:1:0]")
    assert isinstance(address, tuple)
    assert len(address) == 8
    assert Host.serialize(address) == "[1:0:1:0:1:0:1:0]"

    address = Host.parse("[2001:0DB8:85A3:0000:0000:8A2E:0370:7334]")
    assert isinstance(address, tuple)
    assert len(address) == 8
    assert Host.serialize(address) == "[2001:db8:85a3::8a2e:370:7334]"

    address = Host.parse("[::ffff:192.0.2.128]")
    assert isinstance(address, tuple)
    assert len(address) == 8
    assert Host.serialize(address) == "[::ffff:c000:280]"


def test_host_parse_ipv6_01(caplog):
    """Invalid IPv6 address: IPv6-unclosed."""
    caplog.set_level(logging.INFO)

    host = "[1::"
    with pytest.raises(IPv6AddressParseError) as exc_info:
        _ = Host.parse(host)
    assert exc_info.value.args[0] == (
        f"IPv6 address is missing the closing U+005D (]): {host!r}"
    )

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.ERROR
    assert caplog.record_tuples[-1][2] == (
        f"IPv6-unclosed: IPv6 address is missing the closing U+005D (]): {host!r}"
    )


def test_host_parse_ipv6_02(caplog):
    """Invalid IPv6 address: IPv6-invalid-compression."""
    caplog.set_level(logging.INFO)

    address = ":1"
    with pytest.raises(IPv6AddressParseError) as exc_info:
        _ = Host.parse(f"[{address}]")
    assert exc_info.value.args[0] == (
        f"IPv6 address begins with improper compression: {address!r}"
    )

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.ERROR
    assert caplog.record_tuples[-1][2] == (
        "IPv6-invalid-compression: "
        f"IPv6 address begins with improper compression: {address!r}"
    )


def test_host_parse_ipv6_03(caplog):
    """Invalid IPv6 address: IPv6-too-many-pieces."""
    caplog.set_level(logging.INFO)

    address = "1:2:3:4:5:6:7:8:9"
    with pytest.raises(IPv6AddressParseError) as exc_info:
        _ = Host.parse(f"[{address}]")
    assert exc_info.value.args[0] == (
        f"IPv6 address contains more than 8 pieces: {address!r}"
    )

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.ERROR
    assert caplog.record_tuples[-1][2] == (
        "IPv6-too-many-pieces: "
        f"IPv6 address contains more than 8 pieces: {address!r}"
    )


def test_host_parse_ipv6_04(caplog):
    """Invalid IPv6 address: IPv6-multiple-compression."""
    caplog.set_level(logging.INFO)

    address = "1::1::1"
    with pytest.raises(IPv6AddressParseError) as exc_info:
        _ = Host.parse(f"[{address}]")
    assert exc_info.value.args[0] == (
        f"IPv6 address is compressed in more than one spot: {address!r}"
    )

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.ERROR
    assert caplog.record_tuples[-1][2] == (
        "IPv6-multiple-compression: "
        f"IPv6 address is compressed in more than one spot: {address!r}"
    )


def test_host_parse_ipv6_05a(caplog):
    """Invalid IPv6 address: IPv6-invalid-code-point."""
    caplog.set_level(logging.INFO)

    address = "1:2:3!:4"
    with pytest.raises(IPv6AddressParseError) as exc_info:
        _ = Host.parse(f"[{address}]")
    assert exc_info.value.args[0] == (
        "IPv6 address contains a code point that is neither "
        f"an ASCII hex digit nor a U+003A (:): '3!' in {address!r}"
    )

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.ERROR
    assert caplog.record_tuples[-1][2] == (
        "IPv6-invalid-code-point: "
        "IPv6 address contains a code point that is neither "
        f"an ASCII hex digit nor a U+003A (:): '3!' in {address!r}"
    )


def test_host_parse_ipv6_05b(caplog):
    """Invalid IPv6 address: IPv6-invalid-code-point."""
    caplog.set_level(logging.INFO)

    address = "1:2:3:"
    with pytest.raises(IPv6AddressParseError) as exc_info:
        _ = Host.parse(f"[{address}]")
    assert (
        exc_info.value.args[0]
        == f"IPv6 address unexpectedly ends: {address!r}"
    )

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.ERROR
    assert caplog.record_tuples[-1][2] == (
        f"IPv6-invalid-code-point: IPv6 address unexpectedly ends: {address!r}"
    )


def test_host_parse_ipv6_06(caplog):
    """Invalid IPv6 address: IPv6-too-few-pieces."""
    caplog.set_level(logging.INFO)

    address = "1:2:3"
    with pytest.raises(IPv6AddressParseError) as exc_info:
        _ = Host.parse(f"[{address}]")
    assert exc_info.value.args[0] == (
        f"uncompressed IPv6 address contains fewer than 8 pieces: {address!r}"
    )

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.ERROR
    assert caplog.record_tuples[-1][2] == (
        "IPv6-too-few-pieces: "
        f"uncompressed IPv6 address contains fewer than 8 pieces: {address!r}"
    )


def test_host_parse_ipv6_07(caplog):
    """Invalid IPv6 address: IPv4-in-IPv6-too-many-pieces."""
    caplog.set_level(logging.INFO)

    ipv4 = "127.0.0.1"
    address = "1:1:1:1:1:1:1:" + ipv4
    with pytest.raises(IPv6AddressParseError) as exc_info:
        _ = Host.parse(f"[{address}]")
    assert exc_info.value.args[0] == (
        "IPv6 address with IPv4 address syntax: "
        f"IPv6 address has more than 6 pieces: {address!r}"
    )

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.ERROR
    assert caplog.record_tuples[-1][2] == (
        "IPv4-in-IPv6-too-many-pieces: "
        "IPv6 address with IPv4 address syntax: "
        f"IPv6 address has more than 6 pieces: {address!r}"
    )


def test_host_parse_ipv6_08a(caplog):
    """Invalid IPv6 address: IPv4-in-IPv6-invalid-code-point."""
    caplog.set_level(logging.INFO)

    ipv4 = ".0.0.1"
    address = "ffff::" + ipv4
    with pytest.raises(IPv6AddressParseError) as exc_info:
        _ = Host.parse(f"[{address}]")
    assert exc_info.value.args[0] == (
        "IPv6 address with IPv4 address syntax: "
        "IPv4 part is empty or contains a non-ASCII digit / "
        "IPv4 part contains a leading 0 / "
        f"there are too many IPv4 parts: {ipv4!r} in {address!r}"
    )

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.ERROR
    assert caplog.record_tuples[-1][2] == (
        "IPv4-in-IPv6-invalid-code-point: "
        "IPv6 address with IPv4 address syntax: "
        "IPv4 part is empty or contains a non-ASCII digit / "
        "IPv4 part contains a leading 0 / "
        f"there are too many IPv4 parts: {ipv4!r} in {address!r}"
    )


def test_host_parse_ipv6_08b(caplog):
    """Invalid IPv6 address: IPv4-in-IPv6-invalid-code-point."""
    caplog.set_level(logging.INFO)

    ipv4 = "127.0.xyz.1"
    address = "ffff::" + ipv4
    with pytest.raises(IPv6AddressParseError) as exc_info:
        _ = Host.parse(f"[{address}]")
    assert exc_info.value.args[0] == (
        "IPv6 address with IPv4 address syntax: "
        "IPv4 part is empty or contains a non-ASCII digit / "
        "IPv4 part contains a leading 0 / "
        f"there are too many IPv4 parts: {ipv4!r} in {address!r}"
    )

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.ERROR
    assert caplog.record_tuples[-1][2] == (
        "IPv4-in-IPv6-invalid-code-point: "
        "IPv6 address with IPv4 address syntax: "
        "IPv4 part is empty or contains a non-ASCII digit / "
        "IPv4 part contains a leading 0 / "
        f"there are too many IPv4 parts: {ipv4!r} in {address!r}"
    )


def test_host_parse_ipv6_08c(caplog):
    """Invalid IPv6 address: IPv4-in-IPv6-invalid-code-point."""
    caplog.set_level(logging.INFO)

    ipv4 = "127.0xyz"
    address = "ffff::" + ipv4
    with pytest.raises(IPv6AddressParseError) as exc_info:
        _ = Host.parse(f"[{address}]")
    assert exc_info.value.args[0] == (
        "IPv6 address with IPv4 address syntax: "
        "IPv4 part is empty or contains a non-ASCII digit / "
        "IPv4 part contains a leading 0 / "
        f"there are too many IPv4 parts: {ipv4!r} in {address!r}"
    )

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.ERROR
    assert caplog.record_tuples[-1][2] == (
        "IPv4-in-IPv6-invalid-code-point: "
        "IPv6 address with IPv4 address syntax: "
        "IPv4 part is empty or contains a non-ASCII digit / "
        "IPv4 part contains a leading 0 / "
        f"there are too many IPv4 parts: {ipv4!r} in {address!r}"
    )


def test_host_parse_ipv6_08d(caplog):
    """Invalid IPv6 address: IPv4-in-IPv6-invalid-code-point."""
    caplog.set_level(logging.INFO)

    ipv4 = "127.00.0.1"
    address = "ffff::" + ipv4
    with pytest.raises(IPv6AddressParseError) as exc_info:
        _ = Host.parse(f"[{address}]")
    assert exc_info.value.args[0] == (
        "IPv6 address with IPv4 address syntax: "
        "IPv4 part is empty or contains a non-ASCII digit / "
        "IPv4 part contains a leading 0 / "
        f"there are too many IPv4 parts: {ipv4!r} in {address!r}"
    )

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.ERROR
    assert caplog.record_tuples[-1][2] == (
        "IPv4-in-IPv6-invalid-code-point: "
        "IPv6 address with IPv4 address syntax: "
        "IPv4 part is empty or contains a non-ASCII digit / "
        "IPv4 part contains a leading 0 / "
        f"there are too many IPv4 parts: {ipv4!r} in {address!r}"
    )


def test_host_parse_ipv6_08e(caplog):
    """Invalid IPv6 address: IPv4-in-IPv6-invalid-code-point."""
    caplog.set_level(logging.INFO)

    ipv4 = "127.0.0.1.2"
    address = "ffff::" + ipv4
    with pytest.raises(IPv6AddressParseError) as exc_info:
        _ = Host.parse(f"[{address}]")
    assert exc_info.value.args[0] == (
        "IPv6 address with IPv4 address syntax: "
        "IPv4 part is empty or contains a non-ASCII digit / "
        "IPv4 part contains a leading 0 / "
        f"there are too many IPv4 parts: {ipv4!r} in {address!r}"
    )

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.ERROR
    assert caplog.record_tuples[-1][2] == (
        "IPv4-in-IPv6-invalid-code-point: "
        "IPv6 address with IPv4 address syntax: "
        "IPv4 part is empty or contains a non-ASCII digit / "
        "IPv4 part contains a leading 0 / "
        f"there are too many IPv4 parts: {ipv4!r} in {address!r}"
    )


def test_host_parse_ipv6_09(caplog):
    """Invalid IPv6 address: IPv4-in-IPv6-out-of-range-part."""
    caplog.set_level(logging.INFO)

    ipv4 = "127.0.0.4000"
    address = "ffff::" + ipv4
    with pytest.raises(IPv6AddressParseError) as exc_info:
        _ = Host.parse(f"[{address}]")
    assert exc_info.value.args[0] == (
        "IPv6 address with IPv4 address syntax: "
        f"IPv4 part exceeds 255: {ipv4!r} in {address!r}"
    )

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.ERROR
    assert caplog.record_tuples[-1][2] == (
        "IPv4-in-IPv6-out-of-range-part: "
        "IPv6 address with IPv4 address syntax: "
        f"IPv4 part exceeds 255: {ipv4!r} in {address!r}"
    )


def test_host_parse_ipv6_10(caplog):
    """Invalid IPv6 address: IPv4-in-IPv6-too-few-parts."""
    caplog.set_level(logging.INFO)

    ipv4 = "127.0.0"
    address = "ffff::" + ipv4
    with pytest.raises(IPv6AddressParseError) as exc_info:
        _ = Host.parse(f"[{address}]")
    assert exc_info.value.args[0] == (
        "IPv6 address with IPv4 address syntax: "
        f"IPv4 address contains too few parts: {ipv4!r} in {address!r}"
    )

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.ERROR
    assert caplog.record_tuples[-1][2] == (
        "IPv4-in-IPv6-too-few-parts: "
        "IPv6 address with IPv4 address syntax: "
        f"IPv4 address contains too few parts: {ipv4!r} in {address!r}"
    )


def test_host_parse_opaque_host_01(caplog):
    """Contains a forbidden host code point: host-invalid-code-point."""
    caplog.set_level(logging.INFO)

    host = "a<b"
    with pytest.raises(HostParseError) as exc_info:
        _ = Host.parse(host, True)
    assert exc_info.value.args[0] == (
        "opaque host (in a URL that is not special) contains "
        f"a forbidden host code point: {host!r}"
    )

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.ERROR
    assert caplog.record_tuples[-1][2] == (
        "host-invalid-code-point: "
        "opaque host (in a URL that is not special) contains "
        f"a forbidden host code point: {host!r}"
    )


def test_host_parse_opaque_host_02a(caplog):
    """Incorrect percent-encoding: invalid-URL-unit."""
    caplog.set_level(logging.INFO)

    host = "a\ud800b"
    _ = Host.parse(host, True)

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.INFO
    assert caplog.record_tuples[-1][2] == (
        "invalid-URL-unit: code point is found that is not a URL unit: "
        f"U+D800 (\ufffd) in {host!r}"
    )


def test_host_parse_opaque_host_02b(caplog):
    """Incorrect percent-encoding: invalid-URL-unit."""
    caplog.set_level(logging.INFO)

    host = "%zz%66%a.com"
    _ = Host.parse(host, True)

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.INFO
    assert caplog.record_tuples[-1][2] == (
        "invalid-URL-unit: "
        "incorrect percent encoding is found: "
        f"'%zz' in {host!r}"
    )


def test_idna_domain_to_ascii_errors_string():
    errors = IDNA._errors_to_string(0x80003)
    assert (
        errors == "UIDNA_ERROR_EMPTY_LABEL|UIDNA_ERROR_LABEL_TOO_LONG|0x80000"
    )


def test_idna_domain_to_ascii_exceptions(caplog, mocker):
    """domain to ASCII test."""
    caplog.set_level(logging.INFO)
    error_code = icu.ErrorCode()
    error_code.set(icu.U_MEMORY_ALLOCATION_ERROR)
    mocker.patch(
        "icupy.icu.IDNA.name_to_ascii",
        side_effect=icu.ICUError(error_code),
    )

    domain = "a\u200cb"
    with pytest.raises(IDNAError) as exc_info:
        _ = IDNA.domain_to_ascii(domain)
    assert exc_info.value.args[0] == (
        f"Unicode ToASCII failed: domain={domain!r} errors=0x0000 "
        "error_code=<ErrorCode(<U_MEMORY_ALLOCATION_ERROR: 7>)>"
    )
    ex = exc_info.value
    assert isinstance(ex, IDNAError)
    ec = ex.error_code
    assert isinstance(ec, icu.ErrorCode)
    assert ec == icu.U_MEMORY_ALLOCATION_ERROR

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.ERROR
    assert caplog.record_tuples[-1][2] == (
        "domain-to-ASCII: "
        f"Unicode ToASCII failed: domain={domain!r} errors=0x0000 "
        "error_code=<ErrorCode(<U_MEMORY_ALLOCATION_ERROR: 7>)>"
    )


def test_idna_domain_to_ascii_empty_string(caplog, mocker):
    """domain to ASCII: The empty host after the domain to ASCII."""
    caplog.set_level(logging.INFO)

    domain = "\u00ad"
    with pytest.raises(HostParseError) as exc_info:
        _ = IDNA.domain_to_ascii(domain)
    assert exc_info.value.args[0] == (
        f"Unicode ToASCII returns the empty string: {domain!r}"
    )

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.ERROR
    assert caplog.record_tuples[-1][2] == (
        f"domain-to-ASCII: Unicode ToASCII returns the empty string: {domain!r}"
    )


def test_idna_domain_to_ascii_use_std3_rules(caplog):
    """domain to ASCII: A domain contains non-LDH ASCII."""
    caplog.set_level(logging.INFO)
    domain = "a\u2260b\u226Ec\u226Fd"

    assert IDNA.domain_to_ascii(domain) == "xn--abcd-5n9aqdi"
    assert len(caplog.record_tuples) == 0

    assert IDNA.domain_to_ascii(domain, False) == "xn--abcd-5n9aqdi"
    assert len(caplog.record_tuples) == 0

    with pytest.raises(HostParseError) as exc_info:
        _ = IDNA.domain_to_ascii(domain, True)
    assert exc_info.value.args[0] == (
        "Unicode ToASCII records an error: "
        f"domain={domain!r} errors=UIDNA_ERROR_DISALLOWED (0x0080)"
    )

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.ERROR
    assert caplog.record_tuples[-1][2] == (
        "domain-to-ASCII: Unicode ToASCII records an error: "
        f"domain={domain!r} errors=UIDNA_ERROR_DISALLOWED (0x0080)"
    )


@pytest.mark.parametrize(
    ("text", "extra", "valid", "error"),
    [
        ["", None, True, ""],  # empty string
        ["0123456789", None, True, ""],  # ASCII digit
        ["ABCDEFGHIJKLMNOPQRSTUVWXYZ", None, True, ""],  # ASCII upper alpha
        ["abcdefghijklmnopqrstuvwxyz", None, True, ""],  # ASCII lower alpha
        [
            "!$&'()*+,-./:;=?@_~",
            None,
            True,
            "",
        ],  # allowed characters
        [
            "!$&'()*+,-./:;=?@_~%",
            None,
            False,
            "%",
        ],
        [
            "!$&'()*+,-./:;=?@_~",
            "%",
            True,
            "",
        ],
        ["\x9f", None, False, "\x9f"],  # U+00A0 to U+10FFFD
        ["\xa0", None, True, ""],  # U+00A0 to U+10FFFD
        ["\U0010fffd", None, True, ""],  # U+00A0 to U+10FFFD
        ["\U0010fffe", None, False, "\U0010fffe"],  # U+00A0 to U+10FFFD
        ["\ud7ff", None, True, ""],  # leading surrogate: U+D800 to U+DBFF
        [
            "a\ud800",
            None,
            False,
            "\ud800",
        ],  # leading surrogate: U+D800 to U+DBFF
        [
            "a\udbff",
            None,
            False,
            "\udbff",
        ],  # leading surrogate: U+D800 to U+DBFF
        [
            "a\udc00",
            None,
            False,
            "\udc00",
        ],  # trailing surrogate: U+DC00 to U+DFFF
        [
            "a\udfff",
            None,
            False,
            "\udfff",
        ],  # trailing surrogate: U+DC00 to U+DFFF
        [
            "a\ue000",
            None,
            True,
            "",
        ],  # trailing surrogate: U+DC00 to U+DFFF
        ["a\ufdcf", None, True, ""],  # noncharacter: U+FDD0 to U+FDEF
        ["a\ufdd0", None, False, "\ufdd0"],  # noncharacter: U+FDD0 to U+FDEF
        ["a\ufdef", None, False, "\ufdef"],  # noncharacter: U+FDD0 to U+FDEF
        ["a\ufdf0", None, True, ""],  # noncharacter: U+FDD0 to U+FDEF
        ["a\ufffd", None, True, ""],  # noncharacter: U+FFFE
        ["a\ufffe", None, False, "\ufffe"],  # noncharacter: U+FFFE
        ["a\uffff", None, False, "\uffff"],  # noncharacter: U+FFFF
        ["a\U00010000", None, True, ""],  # noncharacter: U+FFFF
    ],
)
def test_is_url_code_points(text, extra, valid, error):
    result = is_url_code_points(text, extra=extra)
    assert isinstance(result, tuple)
    assert len(result) == 2
    assert isinstance(result[0], bool)
    assert isinstance(result[1], str)
    assert result[0] is valid
    if not valid:
        assert result[1] == error


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


def test_parse_url_remove_ascii_tab(caplog):
    """Remove all ASCII tab from the input."""
    caplog.set_level(logging.INFO)

    url = parse_url("ht\ttps://www.\t\texample.com/")
    assert url.href == "https://www.example.com/"

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.INFO
    assert caplog.record_tuples[-1][2].startswith(
        "invalid-URL-unit: remove all ASCII tab or newline from ",
    )


def test_parse_url_remove_ascii_tab_or_newline(caplog):
    """Remove all ASCII tab or newline from the input."""
    caplog.set_level(logging.INFO)

    url = parse_url("ht\tt\nps://www.\t\t\n\rexa\r\nmple.\t\ncom/")
    assert url.href == "https://www.example.com/"

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.INFO
    assert caplog.record_tuples[-1][2].startswith(
        "invalid-URL-unit: remove all ASCII tab or newline from ",
    )


def test_parse_url_remove_newline(caplog):
    """Remove all newline from the input."""
    caplog.set_level(logging.INFO)

    url = parse_url("ht\ntps://www.\r\nexample.com\n\r/\n\n")
    assert url.href == "https://www.example.com/"

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.INFO
    assert caplog.record_tuples[-1][2].startswith(
        "invalid-URL-unit: remove all ASCII tab or newline from ",
    )


def test_parse_url_remove_leading_and_trailing_junk(caplog):
    """Remove any leading and trailing C0 control or space from the input."""
    caplog.set_level(logging.INFO)

    url = parse_url("\x1f\x1e  \x00 https://www.example.com/\x1f\x1e  \x00 ")
    assert url.href == "https://www.example.com/"

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.INFO
    assert caplog.record_tuples[-1][2].startswith(
        "invalid-URL-unit: "
        "remove any leading and trailing C0 control or space from ",
    )


def test_parse_url_remove_leading_junk(caplog):
    """Remove any leading C0 control or space from the input."""
    caplog.set_level(logging.INFO)

    url = parse_url(" \x00  \x1e\x1fhttps://www.example.com/")
    assert url.href == "https://www.example.com/"

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.INFO
    assert caplog.record_tuples[-1][2].startswith(
        "invalid-URL-unit: "
        "remove any leading and trailing C0 control or space from ",
    )


def test_parse_url_remove_trailing_junk(caplog):
    """Remove any trailing C0 control or space from the input."""
    caplog.set_level(logging.INFO)

    url = parse_url("https://www.example.com/ \x00  \x1e\x1f")
    assert url.href == "https://www.example.com/"

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.INFO
    assert caplog.record_tuples[-1][2].startswith(
        "invalid-URL-unit: "
        "remove any leading and trailing C0 control or space from ",
    )


def test_parse_url_authority_state_01(caplog):
    """Validation error in authority state."""
    caplog.set_level(logging.INFO)

    urlstring = "https://@test@test@example:800/"
    base = "http://doesnotmatter/"
    _ = parse_url(urlstring, base)

    assert len(caplog.record_tuples) >= 3
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.INFO
    assert caplog.record_tuples[-1][2] == (
        "invalid-credentials: "
        "input includes credentials: "
        f"{urlstring!r} at position 18"
    )


def test_parse_url_authority_state_02(caplog):
    """Parse error in authority state."""
    caplog.set_level(logging.INFO)

    urlstring = "http://user:pass@/"
    base = "about:blank"
    with pytest.raises(URLParseError) as exc_info:
        _ = parse_url(urlstring, base)
    assert exc_info.value.args[0] == f"credentials are empty: {urlstring!r}"

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.ERROR
    assert caplog.record_tuples[-1][2] == (
        f"invalid-credentials: credentials are empty: {urlstring!r}"
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
    assert caplog.record_tuples[-1][2] == (
        "invalid-reverse-solidus: "
        "URL has a special scheme and it uses U+005C (\\) instead of U+002F (/): "
        f"{urlstring!r} at position 5"
    )


def test_parse_url_file_state_02(caplog):
    """Validation error in file state."""
    caplog.set_level(logging.INFO)

    urlstring = "file:c://foo/bar.html"
    base = "file:///tmp/mock/path"
    _ = parse_url(urlstring, base)

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.INFO
    assert caplog.record_tuples[-1][2] == (
        "file-invalid-Windows-drive-letter: "
        "input is a relative-URL string that starts with a Windows drive letter "
        "and the base URL's scheme is 'file': "
        f"'c:' in {urlstring!r} at position 5"
    )


def test_parse_url_file_host_state(caplog):
    """Validation error in file host state."""
    caplog.set_level(logging.INFO)

    urlstring = "file://c://foo/bar"
    base = "file:///c:/baz/qux"
    _ = parse_url(urlstring, base)

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.INFO
    assert caplog.record_tuples[-1][2] == (
        "file-invalid-Windows-drive-letter-host: "
        "'file:' URL's host is a Windows drive letter: "
        f"'c:' in {urlstring!r} at position 7"
    )


def test_parse_url_file_slash_state(caplog):
    """Validation error in file slash state."""
    caplog.set_level(logging.INFO)

    urlstring = "file:\\\\//"
    base = "about:blank"
    _ = parse_url(urlstring, base)

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.INFO
    assert caplog.record_tuples[-1][2] == (
        "invalid-reverse-solidus: "
        "URL has a special scheme and it uses U+005C (\\) instead of U+002F (/): "
        f"{urlstring!r} at position 6"
    )


def test_parse_url_fragment_state_01(caplog):
    """Validation error in fragment state."""
    caplog.set_level(logging.INFO)

    urlstring = "http://example.org/test?a\ud800b"
    base = "about:blank"
    _ = parse_url(urlstring, base)

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.INFO
    assert caplog.record_tuples[-1][2] == (
        "invalid-URL-unit: code point is found that is not a URL unit: "
        f"U+D800 (\ufffd) in {urlstring!r} at position 25"
    )


def test_parse_url_fragment_state_02a(caplog):
    """Validation error in fragment state."""
    caplog.set_level(logging.INFO)

    urlstring = "http://example.org/test?a#%GH"
    base = "about:blank"
    _ = parse_url(urlstring, base)

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.INFO
    assert caplog.record_tuples[-1][2] == (
        "invalid-URL-unit: incorrect percent encoding is found: "
        f"'%GH' in {urlstring!r} at position 26"
    )


def test_parse_url_fragment_state_02b(caplog):
    """Validation error in fragment state."""
    caplog.set_level(logging.INFO)

    urlstring = "http://example.org/test?a#%F"
    base = "about:blank"
    _ = parse_url(urlstring, base)

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.INFO
    assert caplog.record_tuples[-1][2] == (
        "invalid-URL-unit: incorrect percent encoding is found: "
        f"'%F' in {urlstring!r} at position 26"
    )


def test_parse_url_host_state_01(caplog):
    """Parse error in host state or hostname state."""
    caplog.set_level(logging.INFO)

    urlstring = "sc://:/"
    base = "about:blank"
    with pytest.raises(URLParseError) as exc_info:
        _ = parse_url(urlstring, base)
    assert (
        exc_info.value.args[0]
        == f"input does not contain a host: {urlstring!r}"
    )

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.ERROR
    assert caplog.record_tuples[-1][2] == (
        f"host-missing: input does not contain a host: {urlstring!r}"
    )


def test_parse_url_host_state_02(caplog):
    """Parse error in host state or hostname state. (special scheme)"""
    caplog.set_level(logging.INFO)

    urlstring = "http://"
    base = "about:blank"
    with pytest.raises(URLParseError) as exc_info:
        _ = parse_url(urlstring, base)
    assert exc_info.value.args[0] == (
        f"input has a special scheme, but does not contain a host: {urlstring!r}"
    )

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.ERROR
    assert caplog.record_tuples[-1][2] == (
        "host-missing: "
        f"input has a special scheme, but does not contain a host: {urlstring!r}"
    )


def test_parse_url_no_scheme_state_01(caplog):
    """Parse error in no scheme state."""
    caplog.set_level(logging.INFO)

    urlstring = "////c:/"
    base = None
    with pytest.raises(URLParseError) as exc_info:
        _ = parse_url(urlstring, base)
    assert exc_info.value.args[0] == (
        "input is missing a scheme, because it does not begin with an ASCII alpha, "
        "and either no base URL was provided or the base URL cannot be used "
        "as a base URL because it has an opaque path: "
        f"input={urlstring!r} base={base!r}"
    )

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.ERROR
    assert caplog.record_tuples[-1][2] == (
        "missing-scheme-non-relative-URL: "
        "input is missing a scheme, because it does not begin with an ASCII alpha, "
        "and either no base URL was provided or the base URL cannot be used "
        "as a base URL because it has an opaque path: "
        f"input={urlstring!r} base={base!r}"
    )


def test_parse_url_no_scheme_state_02(caplog):
    """Parse error in no scheme state: with base URL."""
    caplog.set_level(logging.INFO)

    urlstring = "////c:/"
    base = "mailto:user@example.org"
    with pytest.raises(URLParseError) as exc_info:
        _ = parse_url(urlstring, base)
    assert exc_info.value.args[0] == (
        "input is missing a scheme, because it does not begin with an ASCII alpha, "
        "and either no base URL was provided or the base URL cannot be used "
        "as a base URL because it has an opaque path: "
        f"input={urlstring!r} base={base!r}"
    )

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.ERROR
    assert caplog.record_tuples[-1][2] == (
        "missing-scheme-non-relative-URL: "
        "input is missing a scheme, because it does not begin with an ASCII alpha, "
        "and either no base URL was provided or the base URL cannot be used "
        "as a base URL because it has an opaque path: "
        f"input={urlstring!r} base={base!r}"
    )


def test_parse_url_opaque_path_state_01(caplog):
    """Validation error in opaque path state: invalid-URL-unit."""
    caplog.set_level(logging.INFO)

    urlstring = "sc:\\../\U0010fffe%AA/"
    base = "about:blank"
    _ = parse_url(urlstring, base)

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.INFO
    assert caplog.record_tuples[-1][2] == (
        "invalid-URL-unit: code point is found that is not a URL unit: "
        f"U+10FFFE (\U0010fffe) in {urlstring!r} at position 7"
    )


def test_parse_url_opaque_path_state_02a(caplog):
    """Validation error in opaque path state."""
    caplog.set_level(logging.INFO)

    urlstring = "sc:\\../%GH"
    base = "about:blank"
    _ = parse_url(urlstring, base)

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.INFO
    assert caplog.record_tuples[-1][2] == (
        "invalid-URL-unit: incorrect percent encoding is found: "
        f"'%GH' in {urlstring!r} at position 7"
    )


def test_parse_url_opaque_path_state_02b(caplog):
    """Validation error in opaque path state."""
    caplog.set_level(logging.INFO)

    urlstring = "sc:\\../%A"
    base = "about:blank"
    _ = parse_url(urlstring, base)

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.INFO
    assert caplog.record_tuples[-1][2] == (
        "invalid-URL-unit: incorrect percent encoding is found: "
        f"'%A' in {urlstring!r} at position 7"
    )


def test_parse_url_path_state_01(caplog):
    """Validation error in path state."""
    caplog.set_level(logging.INFO)

    urlstring = "http://foo.com/\\@"
    base = "http://example.org/foo/bar"
    _ = parse_url(urlstring, base)

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.INFO
    assert caplog.record_tuples[-1][2] == (
        "invalid-reverse-solidus: "
        "URL has a special scheme and it uses U+005C (\\) instead of U+002F (/): "
        f"{urlstring!r} at position 15"
    )


def test_parse_url_path_state_02a(caplog):
    """Validation error in path state."""
    caplog.set_level(logging.INFO)

    urlstring = "http://foo.com/%GH"
    base = "http://example.org/foo/bar"
    _ = parse_url(urlstring, base)

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.INFO
    assert caplog.record_tuples[-1][2] == (
        "invalid-URL-unit: incorrect percent encoding is found: "
        f"'%GH' in {urlstring!r} at position 15"
    )


def test_parse_url_path_state_02b(caplog):
    """Validation error in path state."""
    caplog.set_level(logging.INFO)

    urlstring = "http://foo.com/%A"
    base = "http://example.org/foo/bar"
    _ = parse_url(urlstring, base)

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.INFO
    assert caplog.record_tuples[-1][2] == (
        "invalid-URL-unit: incorrect percent encoding is found: "
        f"'%A' in {urlstring!r} at position 15"
    )


def test_parse_url_path_state_03(caplog):
    """Validation error in path state."""
    caplog.set_level(logging.INFO)

    urlstring = "http://foo.com/a\ud800b"
    base = "http://example.org/foo/bar"
    _ = parse_url(urlstring, base)

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.INFO
    assert caplog.record_tuples[-1][2] == (
        "invalid-URL-unit: code point is found that is not a URL unit: "
        f"U+D800 (\ufffd) in {urlstring!r} at position 16"
    )


def test_parse_url_path_start_state(caplog):
    """Validation error in path start state."""
    caplog.set_level(logging.INFO)

    urlstring = "\\\\server\\file"
    base = "file:///tmp/mock/path"
    _ = parse_url(urlstring, base)

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.INFO
    assert caplog.record_tuples[-1][2] == (
        "invalid-reverse-solidus: "
        "URL has a special scheme and it uses U+005C (\\) instead of U+002F (/): "
        f"{urlstring!r} at position 8"
    )


def test_parse_url_port_state_01(caplog):
    """Parse error in port state."""
    caplog.set_level(logging.INFO)

    port = 999999
    urlstring = f"http://f:{port}/c"
    base = "about:blank"
    with pytest.raises(URLParseError) as exc_info:
        _ = parse_url(urlstring, base)
    assert exc_info.value.args[0] == (
        f"input's port is too big: {port} in {urlstring!r}"
    )

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.ERROR
    assert caplog.record_tuples[-1][2] == (
        f"port-out-of-range: input's port is too big: {port} in {urlstring!r}"
    )


def test_parse_url_port_state_02(caplog):
    """Parse error in port state."""
    caplog.set_level(logging.INFO)

    urlstring = "http://foo:-80/"
    base = "about:blank"
    with pytest.raises(URLParseError) as exc_info:
        _ = parse_url(urlstring, base)
    assert exc_info.value.args[0] == (
        f"input's port is invalid: {urlstring!r}"
    )

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.ERROR
    assert caplog.record_tuples[-1][2] == (
        f"port-invalid: input's port is invalid: {urlstring!r}"
    )


def test_parse_url_query_state_01(caplog):
    """Validation error in query state."""
    caplog.set_level(logging.INFO)

    urlstring = "http://example.org/test?a\udfffb"
    base = "about:blank"
    _ = parse_url(urlstring, base)

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.INFO
    assert caplog.record_tuples[-1][2] == (
        "invalid-URL-unit: "
        "code point is found that is not a URL unit: "
        f"U+DFFF (\ufffd) in {urlstring!r} at position 25"
    )


def test_parse_url_query_state_02a(caplog):
    """Validation error in query state."""
    caplog.set_level(logging.INFO)

    urlstring = "http://example.org/test?%GH"
    base = "about:blank"
    _ = parse_url(urlstring, base)

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.INFO
    assert caplog.record_tuples[-1][2] == (
        "invalid-URL-unit: "
        "incorrect percent encoding is found: "
        f"'%GH' in {urlstring!r} at position 24"
    )


def test_parse_url_query_state_02b(caplog):
    """Validation error in query state."""
    caplog.set_level(logging.INFO)

    urlstring = "http://example.org/test?%F"
    base = "about:blank"
    _ = parse_url(urlstring, base)

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.INFO
    assert caplog.record_tuples[-1][2] == (
        "invalid-URL-unit: "
        "incorrect percent encoding is found: "
        f"'%F' in {urlstring!r} at position 24"
    )


def test_parse_url_relative_state(caplog):
    """Validation error in relative state."""
    caplog.set_level(logging.INFO)

    urlstring = "\\x"
    base = "http://example.org/foo/bar"
    _ = parse_url(urlstring, base)

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.INFO
    assert caplog.record_tuples[-1][2] == (
        "invalid-reverse-solidus: "
        "URL has a special scheme and it uses U+005C (\\) instead of U+002F (/): "
        f"{urlstring!r} at position 0"
    )


def test_parse_url_relative_slash_state(caplog):
    """Validation error in relative slash state."""
    caplog.set_level(logging.INFO)

    urlstring = "/\\server/file"
    base = "http://example.org/foo/bar"
    _ = parse_url(urlstring, base)

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[-1][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[-1][1] == logging.INFO
    assert caplog.record_tuples[-1][2] == (
        "invalid-reverse-solidus: "
        "URL has a special scheme and it uses U+005C (\\) instead of U+002F (/): "
        f"{urlstring!r} at position 1"
    )


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
    assert exc_info.value.args[0] == (
        f"input's scheme does not begin with an ASCII alpha: {urlstring!r}"
    )

    assert len(caplog.record_tuples) == 0


def test_parse_url_scheme_state_01(caplog):
    """Validation error in scheme state."""
    caplog.set_level(logging.INFO)

    urlstring = "file:\\c:\\foo\\bar"
    base = "about:blank"
    _ = parse_url(urlstring, base)

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[0][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[0][1] == logging.INFO
    assert caplog.record_tuples[0][2] == (
        "special-scheme-missing-following-solidus: "
        "input's scheme is not followed by '//': "
        f"'\\\\c' in {urlstring!r} at position 5"
    )


def test_parse_url_scheme_state_02(caplog):
    """Parse error in scheme state."""
    caplog.set_level(logging.INFO)

    urlstring = "http"
    with pytest.raises(URLParseError) as exc_info:
        _ = BasicURLParser.parse(
            urlstring,
            state_override=URLParserState.SCHEME_START_STATE,
        )
    assert exc_info.value.args[0] == (
        f"input's scheme does not end with U+003A (:): {urlstring!r}"
    )

    assert len(caplog.record_tuples) == 0


def test_parse_url_special_authority_ignore_slashes_state(caplog):
    """Validation error in special authority ignore slashes state."""
    caplog.set_level(logging.INFO)

    urlstring = "///x/"
    base = "http://example.org/"
    _ = parse_url(urlstring, base)

    assert len(caplog.record_tuples) > 0
    print(caplog.record_tuples[0][0])
    assert caplog.record_tuples[0][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[0][1] == logging.INFO
    assert caplog.record_tuples[0][2] == (
        "special-scheme-missing-following-solidus: "
        "input's scheme is not followed by '//': "
        f"U+002F (/) in {urlstring!r} at position 2"
    )


def test_parse_url_special_authority_slashes_state(caplog):
    """Validation error in special authority slashes state."""
    caplog.set_level(logging.INFO)

    urlstring = "http:\\x"
    base = None
    _ = parse_url(urlstring, base)

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[0][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[0][1] == logging.INFO
    assert caplog.record_tuples[0][2] == (
        "special-scheme-missing-following-solidus: "
        "input's scheme is not followed by '//': "
        f"'\\\\x' in {urlstring!r} at position 5"
    )


def test_parse_url_special_relative_or_authority_state(caplog):
    """Validation error in special relative or authority state."""
    caplog.set_level(logging.INFO)

    urlstring = "http:\\x"
    base = "http://example.org/"
    _ = parse_url(urlstring, base)

    assert len(caplog.record_tuples) > 0
    assert caplog.record_tuples[0][0].startswith(_MODULE_NAME)
    assert caplog.record_tuples[0][1] == logging.INFO
    assert caplog.record_tuples[0][2] == (
        "special-scheme-missing-following-solidus: "
        "input's scheme is not followed by '//': "
        f"'\\\\x' in {urlstring!r} at position 5"
    )


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
