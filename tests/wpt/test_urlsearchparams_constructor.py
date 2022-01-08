# References:
#  https://github.com/web-platform-tests/wpt/blob/master/url/urlsearchparams-constructor.any.js

import pytest

from urlstd.parse import URLSearchParams


def test_basic_construction():
    """Basic URLSearchParams construction."""
    params = URLSearchParams()
    assert len(params + "") == 0
    params = URLSearchParams("")
    assert len(params + "") == 0
    params = URLSearchParams("a=b")
    assert params + "" == "a=b"
    params = URLSearchParams(params)
    assert params + "" == "a=b"


def test_no_arguments():
    """URLSearchParams constructor, no arguments."""
    params = URLSearchParams()
    assert len(str(params)) == 0


def test_remove_leading():
    """URLSearchParams constructor, remove leading '?'."""
    params = URLSearchParams("?a=b")
    assert str(params) == "a=b"


def test_empty_string_as_argument():
    """URLSearchParams constructor, empty string as argument."""
    params = URLSearchParams("")
    assert len(str(params)) == 0


def test_empty_dict_as_argument():
    """URLSearchParams constructor, {} as argument."""
    params = URLSearchParams({})
    assert len(params + "") == 0


def test_string():
    """URLSearchParams constructor, string."""
    params = URLSearchParams("a=b")
    assert params.has("a")
    assert not params.has("b")

    params = URLSearchParams("a=b&c")
    assert params.has("a")
    assert params.has("c")

    params = URLSearchParams("&a&&& &&&&&a+b=& c&m%c3%b8%c3%b8")
    assert params.has("a")
    assert params.has("a b")
    assert params.has(" ")
    assert not params.has("c")
    assert params.has(" c")
    assert params.has("møø")

    params = URLSearchParams("id=0&value=%")
    assert params.has("id")
    assert params.has("value")
    assert params.get("id") == "0"
    assert params.get("value") == "%"

    params = URLSearchParams("b=%2sf%2a")
    assert params.has("b")
    assert params.get("b") == "%2sf*"

    params = URLSearchParams("b=%2%2af%2a")
    assert params.has("b")
    assert params.get("b") == "%2*f*"

    params = URLSearchParams("b=%%2a")
    assert params.has("b")
    assert params.get("b") == "%*"


def test_object():
    """URLSearchParams constructor, object."""
    seed = URLSearchParams("a=b&c=d")
    params = URLSearchParams(seed)
    assert params.get("a") == "b"
    assert params.get("c") == "d"
    assert not params.has("d")

    seed.append("e", "f")
    assert not params.has("e")
    params.append("g", "h")
    assert not seed.has("g")


def test_parse_plus():
    """Parse +"""
    params = URLSearchParams("a=b+c")
    assert params.get("a") == "b c"
    params = URLSearchParams("a+b=c")
    assert params.get("a b") == "c"


def test_parse_encoded_plus():
    """Parse encoded +"""
    test_value = "+15555555555"
    params = URLSearchParams()
    params.set("query", test_value)
    new_params = URLSearchParams(str(params))

    assert str(params) == "query=%2B15555555555"
    assert params.get("query") == test_value
    assert new_params.get("query") == test_value


def test_parse_space():
    """Parse space"""
    params = URLSearchParams("a=b c")
    assert params.get("a") == "b c"
    params = URLSearchParams("a b=c")
    assert params.get("a b") == "c"


def test_parse_percent_encoded_20():
    """Parse %20"""
    params = URLSearchParams("a=b%20c")
    assert params.get("a") == "b c"
    params = URLSearchParams("a%20b=c")
    assert params.get("a b") == "c"


def test_parse_00():
    """Parse \\0"""
    params = URLSearchParams("a=b\0c")
    assert params.get("a") == "b\0c"
    params = URLSearchParams("a\0b=c")
    assert params.get("a\0b") == "c"


def test_parse_percent_encoded_00():
    """Parse %00"""
    params = URLSearchParams("a=b%00c")
    assert params.get("a") == "b\0c"
    params = URLSearchParams("a%00b=c")
    assert params.get("a\0b") == "c"


def test_parse_2384():
    """Parse \\u2384"""
    params = URLSearchParams("a=b\u2384")
    assert params.get("a") == "b\u2384"
    params = URLSearchParams("a\u2384b=c")
    assert params.get("a\u2384b") == "c"


def test_parse_percent_encoded_2384():
    """Parse %e2%8e%84"""
    params = URLSearchParams("a=b%e2%8e%84")
    assert params.get("a") == "b\u2384"
    params = URLSearchParams("a%e2%8e%84b=c")
    assert params.get("a\u2384b") == "c"


def test_parse_d83d_dca9():
    """Parse \\uD83D\\uDCA9"""
    params = URLSearchParams("a=b\uD83D\uDCA9c")
    # assert params.get("a") == "b\uD83D\uDCA9c", list(params)
    # NOTE: "b\uD83D\uDCA9c" and "b\U0001F4A9c" are not equal in Python.
    assert params.get("a") == "b\U0001F4A9c", list(params)
    params = URLSearchParams("a\uD83D\uDCA9b=c")
    assert params.get("a\uD83D\uDCA9b") == "c", list(params)


def test_parse_percent_encoded_d83d_dca9():
    """Parse %f0%9f%92%a9"""
    params = URLSearchParams("a=b%f0%9f%92%a9c")
    # assert params.get("a") == "b\uD83D\uDCA9c", list(params)
    # NOTE: "b\uD83D\uDCA9c" and "b\U0001F4A9c" are not equal in Python.
    assert params.get("a") == "b\U0001F4A9c", list(params)
    params = URLSearchParams("a%f0%9f%92%a9b=c")
    assert params.get("a\uD83D\uDCA9b") == "c", list(params)


def test_sequences_of_strings():
    """Constructor with sequence of sequences of strings."""
    params = URLSearchParams([["a", "b"], ["c", "d"]])
    assert params.get("a") == "b", list(params)
    assert params.get("c") == "d", list(params)
    with pytest.raises(ValueError):
        _ = URLSearchParams([[1]])  # noqa
    with pytest.raises(ValueError):
        _ = URLSearchParams([[1, 2, 3]])  # noqa


@pytest.mark.parametrize(
    "val",
    [
        {
            "input": {"+": "%C2"},
            "output": [["+", "%C2"]],
            "name": "object with +",
        },
        {
            "input": {"c": "x", "a": "?"},
            "output": [["c", "x"], ["a", "?"]],
            "name": "object with two keys",
        },
        {
            "input": [["c", "x"], ["a", "?"]],
            "output": [["c", "x"], ["a", "?"]],
            "name": "array with two keys",
        },
        {
            "input": {"\uD835x": "1", "xx": "2", "\uD83Dx": "3"},
            "output": [["\uFFFDx", "3"], ["xx", "2"]],
            "name": "2 unpaired surrogates (no trailing)",
        },
        {
            "input": {"x\uDC53": "1", "x\uDC5C": "2", "x\uDC65": "3"},
            "output": [["x\uFFFD", "3"]],
            "name": "3 unpaired surrogates (no leading)",
        },
        {
            "input": {"a\0b": "42", "c\uD83D": "23", "d\u1234": "foo"},
            "output": [["a\0b", "42"], ["c\uFFFD", "23"], ["d\u1234", "foo"]],
            "name": "object with NULL, non-ASCII, and surrogate keys",
        },
    ],
)
def test_construct_with(val):
    test_construct_with.__doc__ = msg = "Construct with " + val["name"]
    params = URLSearchParams(val["input"])
    assert list(params) == [tuple(x) for x in val["output"]], msg
