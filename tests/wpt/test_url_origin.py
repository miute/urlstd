# References:
#  https://github.com/web-platform-tests/wpt/blob/dcf353e2846063d4b9e62ec75545d0ea857ef765/url/url-origin.any.js

import logging

import pytest

from urlstd.parse import URL

from . import urltestdata

url_tests = [x for x in urltestdata if "origin" in x]


@pytest.mark.parametrize("expected", url_tests)
def test_origin(expected, caplog):
    caplog.set_level(logging.INFO)
    base = expected.get("base")
    msg = f'Origin parsing: <{expected["input"]}> '
    msg += f"against <{base}>" if base is not None else "without base"
    test_origin.__doc__ = msg

    url = URL(expected["input"], base)
    assert url.origin == expected["origin"], msg
