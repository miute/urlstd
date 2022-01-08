# References:
#  https://github.com/web-platform-tests/wpt/blob/master/url/urlsearchparams-sort.any.js

import pytest

from urlstd.parse import URL, URLSearchParams

tests = [
    {
        "input": "z=b&a=b&z=a&a=a",
        "output": [["a", "b"], ["a", "a"], ["z", "b"], ["z", "a"]],
    },
    {
        "input": "\uFFFD=x&\uFFFC&\uFFFD=a",
        "output": [["\uFFFC", ""], ["\uFFFD", "x"], ["\uFFFD", "a"]],
    },
    {
        "input": "ﬃ&🌈",
        # 🌈 > code point, but < code unit because two code units
        "output": [["🌈", ""], ["ﬃ", ""]],
    },
    {
        "input": "é&e\uFFFD&e\u0301",
        "output": [["e\u0301", ""], ["e\uFFFD", ""], ["é", ""]],
    },
    {
        "input": "z=z&a=a&z=y&a=b&z=x&a=c&z=w&a=d&z=v&a=e&z=u&a=f&z=t&a=g",
        "output": [
            ["a", "a"],
            ["a", "b"],
            ["a", "c"],
            ["a", "d"],
            ["a", "e"],
            ["a", "f"],
            ["a", "g"],
            ["z", "z"],
            ["z", "y"],
            ["z", "x"],
            ["z", "w"],
            ["z", "v"],
            ["z", "u"],
            ["z", "t"],
        ],
    },
    {
        "input": "bbb&bb&aaa&aa=x&aa=y",
        "output": [
            ["aa", "x"],
            ["aa", "y"],
            ["aaa", ""],
            ["bb", ""],
            ["bbb", ""],
        ],
    },
    {
        "input": "z=z&=f&=t&=x",
        "output": [["", "f"], ["", "t"], ["", "x"], ["z", "z"]],
    },
    {"input": "a🌈&a💩", "output": [["a🌈", ""], ["a💩", ""]]},
]


@pytest.mark.parametrize("val", tests)
def test_parse_and_sort(val):
    test_parse_and_sort.__doc__ = msg = "Parse and sort: " + val["input"]
    params = URLSearchParams(val["input"])
    params.sort()
    assert list(params) == [tuple(x) for x in val["output"]], msg


@pytest.mark.parametrize("val", tests)
def test_url_parse_and_sort(val):
    test_url_parse_and_sort.__doc__ = msg = (
        "URL parse and sort: " + val["input"]
    )
    url = URL("?" + val["input"], "https://example/")
    url.search_params.sort()
    params = URLSearchParams(url.search)
    assert list(params) == [tuple(x) for x in val["output"]], msg


def test_sorting_non_existent_params():
    """Sorting non-existent params removes ? from URL."""
    url = URL("http://example.com/?")
    url.search_params.sort()
    assert url.href == "http://example.com/"
    assert len(url.search) == 0
