# References:
#  https://github.com/web-platform-tests/wpt/blob/master/url/urlsearchparams-get.any.js

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
    assert params.has("first"), 'Search params object has name "first"'
    assert (
        params.get("first") == "second"
    ), 'Search params object has name "first" with value "second"'
    value = params.get("third")
    assert (
        isinstance(value, str) and len(value) == 0
    ), 'Search params object has name "third" with the empty value.'
    assert (
        params.get("fourth") is None
    ), 'Search params object has no "fourth" name and value.'
