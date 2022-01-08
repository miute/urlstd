"""
Exception classes raised by urlstd
"""

__all__ = ["URLParseError"]


class URLParseError(ValueError):
    """Exception that raised when URL parsing fails."""

    pass
