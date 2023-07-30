# References:
#  https://github.com/web-platform-tests/wpt/blob/dcf353e2846063d4b9e62ec75545d0ea857ef765/url/urlsearchparams-append.any.js

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


# TODO: Add support for null (URLSearchParams.append()).


def test_append_multiple():
    """Append multiple."""
    params = URLSearchParams()
    params.append("first", 1)
    params.append("second", 2)
    params.append("third", "")
    params.append("first", 10)
    assert params.has("first")
    assert params.get("first") == "1"
    assert params.get("second") == "2"
    result = params.get("third")
    assert isinstance(result, str) and len(result) == 0
    params.append("first", 10)
    assert params.get("first") == "1"
