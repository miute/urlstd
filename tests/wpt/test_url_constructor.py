# References:
#  https://github.com/web-platform-tests/wpt/blob/master/url/url-constructor.any.js

import logging

import pytest

from urlstd.error import URLParseError
from urlstd.parse import URL

from . import urltestdata as urltests


@pytest.mark.parametrize("expected", urltests)
def test_url(expected, caplog):
    caplog.set_level(logging.INFO)
    test_url.__doc__ = msg = "Parsing: <{input}> against <{base}>".format(
        input=expected["input"], base=expected["base"]
    )
    if expected.get("failure", False):
        with pytest.raises(URLParseError):
            _ = URL(expected["input"], expected["base"])
        return

    url = URL(expected["input"], expected["base"])
    assert url.href == expected["href"], msg
    assert url.protocol == expected["protocol"], msg
    assert url.username == expected["username"], msg
    assert url.password == expected["password"], msg
    assert url.host == expected["host"], msg
    assert url.hostname == expected["hostname"], msg
    assert url.port == expected["port"], msg
    assert url.pathname == expected["pathname"], msg
    assert url.search == expected["search"], msg
    if "searchParams" in expected:
        assert str(url.search_params) == expected["searchParams"], msg
    assert url.hash == expected["hash"], msg
