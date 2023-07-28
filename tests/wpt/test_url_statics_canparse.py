# References:
#   https://github.com/web-platform-tests/wpt/blob/master/url/url-statics-canparse.any.js

import pytest

from urlstd.parse import URL


@pytest.mark.parametrize(
    ("url", "base", "expected"),
    [
        # [None, None, False],
        ["a:b", None, True],
        # [None, "a:b", False],
        ["a:/b", None, True],
        # [None, "a:/b", True],
        ["https://test:test", None, False],
        ["a", "https://b/", True],
    ],
)
def test_setter(url, base, expected):
    assert (
        URL.can_parse(url, base) is expected
    ), f"URL.can_parse({url!r}, {base!r})"
