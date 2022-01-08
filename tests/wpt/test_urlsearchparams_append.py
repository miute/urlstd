# References:
#  https://github.com/web-platform-tests/wpt/blob/master/url/urlsearchparams-append.any.js

from urlstd.parse import URLSearchParams


def test_append_same_name():
    """Append same name."""
    params = URLSearchParams()
    params.append("a", "b")
    assert params + "" == "a=b"
    params.append("a", "b")
    assert params + "" == "a=b&a=b"
    params.append("a", "c")
    assert params + "" == "a=b&a=b&a=c"


def test_append_empty_strings():
    """Append empty strings."""
    params = URLSearchParams()
    params.append("", "")
    assert params + "" == "="
    params.append("", "")
    assert params + "" == "=&="


def test_append_multiple():
    """Append multiple."""
    params = URLSearchParams()
    params.append("first", 1)
    params.append("second", 2)
    params.append("third", "")
    params.append("first", 10)
    assert params.has("first"), 'Search params object has name "first"'
    assert (
        params.get("first") == "1"
    ), 'Search params object has name "first" with value "1"'
    assert (
        params.get("second") == "2"
    ), 'Search params object has name "second" with value "2"'
    result = params.get("third")
    assert (
        isinstance(result, str) and len(result) == 0
    ), 'Search params object has name "third" with value ""'
    params.append("first", 10)
    assert (
        params.get("first") == "1"
    ), 'Search params object has name "first" with value "1"'
