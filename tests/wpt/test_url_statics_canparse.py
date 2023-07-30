# References:
#  https://github.com/web-platform-tests/wpt/blob/dcf353e2846063d4b9e62ec75545d0ea857ef765/url/url-statics-canparse.any.js

import pytest

from urlstd.parse import URL


@pytest.mark.parametrize(
    ("url", "base", "expected"),
    [
        # [None, None, False],  # undefined, undefined, false
        ["a:b", None, True],  # "a:b", undefined, true
        # [None, "a:b", False],  # undefined, "a:b", false
        ["a:/b", None, True],  # "a:/b", undefined, true
        # [None, "a:/b", True],  # undefined, "a:/b", true
        [
            "https://test:test",
            None,
            False,
        ],  # "https://test:test", undefined, false
        ["a", "https://b/", True],
    ],
)
def test_setter(url, base, expected):
    test_setter.__doc__ = msg = f"URL.canParse({url!r}, {base!r})"

    assert URL.can_parse(url, base) is expected, msg
