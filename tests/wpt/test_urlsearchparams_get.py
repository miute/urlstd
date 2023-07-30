# References:
#  https://github.com/web-platform-tests/wpt/blob/dcf353e2846063d4b9e62ec75545d0ea857ef765/url/urlsearchparams-get.any.js

from urlstd.parse import URLSearchParams


def test_get_basics():
    """Get basics."""
    params = URLSearchParams("a=b&c=d")
    assert params.get("a") == "b"
    assert params.get("c") == "d"
    assert params.get("e") is None
    params = URLSearchParams("a=b&c=d&a=e")
    assert params.get("a") == "b"
    params = URLSearchParams("=b&c=d")
    assert params.get("") == "b"
    params = URLSearchParams("a=&c=d&a=e")
    value = params.get("a")
    assert isinstance(value, str) and len(value) == 0


def test_more_get_basics():
    """More get() basics."""
    params = URLSearchParams("first=second&third&&")
    assert params.has("first")
    assert params.get("first") == "second"
    value = params.get("third")
    assert isinstance(value, str) and len(value) == 0
    assert params.get("fourth") is None
