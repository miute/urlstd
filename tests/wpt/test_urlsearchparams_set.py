# References:
#  https://github.com/web-platform-tests/wpt/blob/dcf353e2846063d4b9e62ec75545d0ea857ef765/url/urlsearchparams-set.any.js

from urlstd.parse import URLSearchParams


def test_set_basics():
    """Set basics."""
    params = URLSearchParams("a=b&c=d")
    params.set("a", "B")
    assert params + "" == "a=B&c=d"
    params = URLSearchParams("a=b&c=d&a=e")
    params.set("a", "B")
    assert params + "" == "a=B&c=d"
    params.set("e", "f")
    assert params + "" == "a=B&c=d&e=f"


def test_url_search_params_set():
    """URLSearchParams.set."""
    params = URLSearchParams("a=1&a=2&a=3")
    assert params.has("a")
    assert params.get("a") == "1"
    params.set("first", 4)
    assert params.has("a")
    assert params.get("a") == "1"
    params.set("a", 4)
    assert params.has("a")
    assert params.get("a") == "4"
