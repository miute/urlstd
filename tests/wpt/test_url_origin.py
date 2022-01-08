# References:
#  https://github.com/web-platform-tests/wpt/blob/master/url/url-origin.any.js

import logging

import pytest

from urlstd.parse import URL

from . import urltestdata

urltests = [x for x in urltestdata if "origin" in x]


@pytest.mark.parametrize("expected", urltests)
def test_origin(expected, caplog):
    caplog.set_level(logging.INFO)
    test_origin.__doc__ = (
        msg
    ) = "Origin parsing: <{input}> against <{base}>".format(
        input=expected["input"], base=expected["base"]
    )
    url = URL(expected["input"], expected["base"])
    assert url.origin == expected["origin"], msg
