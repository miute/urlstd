# References:
#  https://github.com/web-platform-tests/wpt/blob/dcf353e2846063d4b9e62ec75545d0ea857ef765/url/urlsearchparams-sort.any.js

import pytest

from urlstd.parse import URL, URLSearchParams

tests = [
    {
        "input": "z=b&a=b&z=a&a=a",
        "output": [["a", "b"], ["a", "a"], ["z", "b"], ["z", "a"]],
    },
    {
        "input": "\ufffd=x&\ufffc&\ufffd=a",
        "output": [["\ufffc", ""], ["\ufffd", "x"], ["\ufffd", "a"]],
    },
    {
        "input": "ﬃ&🌈",
        # 🌈 > code point, but < code unit because two code units
        "output": [["🌈", ""], ["ﬃ", ""]],
    },
    {
        "input": "é&e\ufffd&e\u0301",
        "output": [["e\u0301", ""], ["e\ufffd", ""], ["é", ""]],
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
    test_parse_and_sort.__doc__ = msg = f"Parse and sort: {val['input']!r}"

    params = URLSearchParams(val["input"])
    params.sort()
    assert list(params) == [tuple(x) for x in val["output"]], msg


@pytest.mark.parametrize("val", tests)
def test_url_parse_and_sort(val):
    msg = f"URL parse and sort: {val['input']!r}"
    test_url_parse_and_sort.__doc__ = msg

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
