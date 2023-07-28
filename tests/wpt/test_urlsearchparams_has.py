# References:
#  https://github.com/web-platform-tests/wpt/blob/master/url/urlsearchparams-has.any.js

from urlstd.parse import URLSearchParams


def test_has_basics():
    """Has basics."""
    params = URLSearchParams("a=b&c=d")
    assert params.has("a")
    assert params.has("c")
    assert not params.has("e")
    params = URLSearchParams("a=b&c=d&a=e")
    assert params.has("a")
    params = URLSearchParams("=b&c=d")
    assert params.has("")
    params = URLSearchParams("null=a")
    assert params.has("null")  # FIXME: Add support for null (None)?


def test_has_following_delete():
    """has() following delete()."""
    params = URLSearchParams("a=b&c=d&&")
    params.append("first", 1)
    params.append("first", 2)
    assert params.has("a"), 'Search params object has name "a"'
    assert params.has("c"), 'Search params object has name "c"'
    assert params.has("first"), 'Search params object has name "first"'
    assert not params.has("d"), 'Search params object has no name "d"'
    params.delete("first")
    assert not params.has("first"), 'Search params object has no name "first"'


def test_two_argument_has():
    """Two-argument has."""
    params = URLSearchParams("a=b&a=d&c&e&")
    assert params.has("a", "b")
    assert not params.has("a", "c")
    assert params.has("a", "d")
    assert params.has("e", "")
    params.append("first", "null")  # TODO: accept null/None.
    assert not params.has("first", "")
    assert params.has("first", "null")
    params.delete("a", "b")
    assert params.has("a", "d")
