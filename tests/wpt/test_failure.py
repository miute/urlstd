# References:
#  https://github.com/web-platform-tests/wpt/blob/a02414f05f77a80e55c7a4c3550fec4b4e3e27ee/url/failure.html

import logging

import pytest

from urlstd.error import URLParseError
from urlstd.parse import URL

from . import urltestdata

test_data = [
    x for x in urltestdata if x.get("failure", False) and x["base"] is None
]


@pytest.mark.parametrize("test", test_data)
def test_url_constructor(test, caplog):
    caplog.set_level(logging.INFO)
    name = f"{test['input']!r} should throw"
    test_url_constructor.__doc__ = "URL's constructor's base argument: " + name

    with pytest.raises(URLParseError):
        _ = URL("about:blank", test["input"])


@pytest.mark.parametrize("test", test_data)
def test_url_href(test, caplog):
    caplog.set_level(logging.INFO)
    name = f"{test['input']!r} should throw"
    test_url_href.__doc__ = "URL's href: " + name

    url = URL("about:blank")
    with pytest.raises(URLParseError):
        url.href = test["input"]
