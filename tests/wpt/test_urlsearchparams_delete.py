# References:
#  https://github.com/web-platform-tests/wpt/blob/dcf353e2846063d4b9e62ec75545d0ea857ef765/url/urlsearchparams-delete.any.js

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

    # TODO: Add support for null (URLSearchParams.delete()).


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


def test_changing_query_of_url_with_opaque_path():
    """Changing the query of a URL with an opaque path can impact the path."""
    url = URL("data:space    ?test")
    assert url.search_params.has("test")
    url.search_params.delete("test")
    assert not url.search_params.has("test")
    assert len(url.search) == 0
    assert url.pathname == "space"
    assert url.href == "data:space"


def test_changing_query_of_url_with_opaque_path_no_fragment():
    """Changing the query of a URL with an opaque path can impact the path
    if the URL has no fragment.
    """
    url = URL("data:space    ?test#test")
    url.search_params.delete("test")
    assert len(url.search) == 0
    assert url.pathname == "space    "
    assert url.href == "data:space    #test"


def test_two_argument_delete():
    """Two-argument delete()."""
    params = URLSearchParams()
    params.append("a", "b")
    params.append("a", "c")
    params.append("a", "d")
    params.delete("a", "c")
    assert str(params) == "a=b&a=d"
