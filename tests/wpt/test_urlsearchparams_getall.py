# References:
#  https://github.com/web-platform-tests/wpt/blob/dcf353e2846063d4b9e62ec75545d0ea857ef765/url/urlsearchparams-getall.any.js

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
    assert params.has("a")
    matches = params.get_all("a")
    assert len(matches) == 4
    assert matches == (
        "1",
        "2",
        "3",
        "",
    )
    params.set("a", "one")
    assert params.get("a") == "one"
    matches = params.get_all("a")
    assert len(matches) == 1
    assert matches == ("one",)
