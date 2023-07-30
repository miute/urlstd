# References:
#  https://github.com/web-platform-tests/wpt/blob/dcf353e2846063d4b9e62ec75545d0ea857ef765/url/url-constructor.any.js

import logging

import pytest

from urlstd.error import URLParseError
from urlstd.parse import URL

from . import urltestdata as url_tests


@pytest.mark.parametrize("expected", url_tests)
def test_url(expected, caplog):
    caplog.set_level(logging.INFO)
    base = expected.get("base")
    msg = f'Parsing: <{expected["input"]}> '
    msg += f"against <{base}>" if base is not None else "without base"
    test_url.__doc__ = msg

    if expected.get("failure", False):
        with pytest.raises(URLParseError):
            _ = URL(expected["input"], base)
        return

    url = URL(expected["input"], base)
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
