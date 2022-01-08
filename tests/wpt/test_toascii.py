# References:
#  https://github.com/web-platform-tests/wpt/blob/master/url/toascii.window.js

import itertools
import logging

import pytest

from urlstd.parse import URL, URLParseError

from . import toascii as tests


@pytest.mark.parametrize("host_test", tests)
def test_getter(host_test, caplog):
    test_getter.__doc__ = msg = host_test["input"] + " (using URL)"
    caplog.set_level(logging.INFO)
    urlstring = "https://%s/x" % host_test["input"]
    if host_test["output"]:
        url = URL(urlstring)
        assert url.host == host_test["output"], msg
        assert url.hostname == host_test["output"], msg
        assert url.pathname == "/x", msg
        href = "https://%s/x" % host_test["output"]
        assert url.href == href, msg
    else:
        with pytest.raises(URLParseError):
            _ = URL(urlstring)


@pytest.mark.parametrize(
    ("host_test", "val"), itertools.product(tests, ["host", "hostname"])
)
def test_setter(host_test, val, caplog):
    caplog.set_level(logging.INFO)
    test_setter.__doc__ = msg = host_test["input"] + f" (using URL.{val})"  # type: ignore  # noqa
    urlstring = "https://x/x"
    url = URL(urlstring)
    try:
        setattr(url, val, host_test["input"])  # type: ignore
    except URLParseError:
        pass
    if host_test["output"]:  # type: ignore
        assert getattr(url, val) == host_test["output"], msg  # type: ignore
    else:
        assert getattr(url, val) == "x"  # type: ignore
