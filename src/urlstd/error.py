"""
Exception classes raised by urlstd
"""

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
    """Exception that raised when IDNA processing fails."""


class HostParseError(URLParseError):
    """Exception that raised when host parsing fails."""


class IPv4AddressParseError(HostParseError):
    """Exception that raised when IPv4 address parsing fails."""


class IPv6AddressParseError(HostParseError):
    """Exception that raised when IPv6 address parsing fails."""
