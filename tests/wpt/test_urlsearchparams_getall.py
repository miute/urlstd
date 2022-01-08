# References:
#  https://github.com/web-platform-tests/wpt/blob/master/url/urlsearchparams-getall.any.js

from urlstd.parse import URLSearchParams


def test_get_all_basics():
    """getAll() basics."""
    params = URLSearchParams("a=b&c=d")
    assert params.get_all("a") == ("b",)
    assert params.get_all("c") == ("d",)
    assert params.get_all("e") == ()
    params = URLSearchParams("a=b&c=d&a=e")
    assert params.get_all("a") == ("b", "e")
    params = URLSearchParams("=b&c=d")
    assert params.get_all("") == ("b",)
    params = URLSearchParams("a=&c=d&a=e")
    assert params.get_all("a") == ("", "e")


def test_get_all_multiples():
    """getAll() multiples."""
    params = URLSearchParams("a=1&a=2&a=3&a")
    assert params.has("a"), 'Search params object has name "a"'
    matches = params.get_all("a")
    assert len(matches) == 4, 'Search params object has values for name "a"'
    assert matches == (
        "1",
        "2",
        "3",
        "",
    ), 'Search params object has expected name "a" values'
    params.set("a", "one")
    assert (
        params.get("a") == "one"
    ), 'Search params object has name "a" with value "one"'
    matches = params.get_all("a")
    assert len(matches) == 1, 'Search params object has values for name "a"'
    assert matches == (
        "one",
    ), 'Search params object has expected name "a" values'
