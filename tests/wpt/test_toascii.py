# References:
#  https://github.com/web-platform-tests/wpt/blob/a02414f05f77a80e55c7a4c3550fec4b4e3e27ee/url/toascii.window.js

import itertools
import logging

import pytest

from urlstd.parse import URL, URLParseError

from . import toascii as tests


def _make_url(string: str) -> URL:
    return URL(f"https://{string}/x")


@pytest.mark.parametrize("host_test", tests)
def test_getter(host_test, caplog):
    test_getter.__doc__ = msg = f"{host_test['input']!r} (using URL)"
    caplog.set_level(logging.INFO)

    if host_test["output"] is not None:
        url = _make_url(host_test["input"])
        assert url.host == host_test["output"], msg
        assert url.hostname == host_test["output"], msg
        assert url.pathname == "/x", msg
        assert url.href == f"https://{host_test['output']}/x", msg
    else:
        with pytest.raises(URLParseError):
            _ = _make_url(host_test["input"])


@pytest.mark.parametrize(
    ("host_test", "val"), itertools.product(tests, ["host", "hostname"])
)
def test_setter(host_test, val, caplog):
    caplog.set_level(logging.INFO)
    test_setter.__doc__ = msg = f"{host_test['input']!r} (using URL.{val})"

    url = _make_url("x")
    try:
        setattr(url, val, host_test["input"])  # type: ignore
    except URLParseError:
        pass
    if host_test["output"] is not None:
        assert getattr(url, val) == host_test["output"], msg  # type: ignore
    else:
        assert getattr(url, val) == "x", msg  # type: ignore
