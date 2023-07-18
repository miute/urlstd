"""
Exception classes raised by urlstd
"""

import icupy.icu as icu

__all__ = [
    "HostParseError",
    "IDNAError",
    "IPv4AddressParseError",
    "IPv6AddressParseError",
    "URLParseError",
]


class URLParseError(ValueError):
    """Exception that raised when URL parsing fails."""


class IDNAError(URLParseError):
    """Exception that raised when IDNA processing fails.

    Args:
        message: An error message.
        error_code: icupy.icu.ErrorCode object.
    """

    def __init__(self, message: str, error_code: icu.ErrorCode) -> None:
        super().__init__(f"{message} error_code={error_code!r}")
        self._error_code = error_code

    @property
    def error_code(self) -> icu.ErrorCode:
        """icupy.icu.ErrorCode: The object of wrapper class for
        `UErrorCode
        <https://unicode-org.github.io/icu-docs/apidoc/released/icu4c/utypes_8h.html>`_
        used in ICU C/C++ APIs.
        See `icu::ErrorCode
        <https://unicode-org.github.io/icu-docs/apidoc/released/icu4c/classicu_1_1ErrorCode.html>`_
        for more details.
        """
        return self._error_code


class HostParseError(URLParseError):
    """Exception that raised when host parsing fails."""


class IPv4AddressParseError(HostParseError):
    """Exception that raised when IPv4 address parsing fails."""


class IPv6AddressParseError(HostParseError):
    """Exception that raised when IPv6 address parsing fails."""
