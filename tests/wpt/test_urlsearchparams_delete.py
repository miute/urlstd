# References:
#  https://github.com/web-platform-tests/wpt/blob/master/url/urlsearchparams-delete.any.js

from urlstd.parse import URL, URLSearchParams


def test_delete_basics():
    """Delete basics."""
    params = URLSearchParams("a=b&c=d")
    params.delete("a")
    assert params + "" == "c=d"

    params = URLSearchParams("a=a&b=b&a=a&c=c")
    params.delete("a")
    assert params + "" == "b=b&c=c"

    params = URLSearchParams("a=a&=&b=b&c=c")
    params.delete("")
    assert params + "" == "a=a&b=b&c=c"


def test_deleting_appended_multiple():
    """Deleting appended multiple."""
    params = URLSearchParams()
    params.append("first", "1")
    assert params.has("first")
    assert params.get("first") == "1"

    params.delete("first")
    assert not params.has("first")

    params.append("first", "1")
    params.append("first", "10")
    params.delete("first")
    assert not params.has("first")


def test_deleting_all_params():
    """Deleting all params removes ? from URL."""
    url = URL("http://example.com/?param1&param2")
    url.search_params.delete("param1")
    url.search_params.delete("param2")
    assert url.href == "http://example.com/"
    assert len(url.search) == 0


def test_removing_non_existent_param():
    """Removing non-existent param removes ? from URL."""
    url = URL("http://example.com/?")
    url.search_params.delete("param1")
    assert url.href == "http://example.com/"
    assert len(url.search) == 0
