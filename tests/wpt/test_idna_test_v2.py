# References:
#  https://github.com/web-platform-tests/wpt/blob/dcf353e2846063d4b9e62ec75545d0ea857ef765/url/IdnaTestV2.window.js

import logging

import pytest

from urlstd.parse import (
    SAFE_COMPONENT_PERCENT_ENCODE_SET,
    URL,
    URLParseError,
    string_percent_encode,
)

from . import idna_tests


def _encode_host_ending_code_points(s: str):
    output = ""
    for c in s:
        if c in [":", "/", "?", "#", "\\"]:
            output += _encode_uri_component(c)
        else:
            output += c
    return output


def _encode_uri_component(s: str):
    return string_percent_encode(s, safe=SAFE_COMPONENT_PERCENT_ENCODE_SET)


@pytest.mark.parametrize("idna_test", idna_tests)
def test_to_ascii(caplog, idna_test):
    comment = " " + idna_test.get("comment", "")
    test_to_ascii.__doc__ = msg = (
        f'ToASCII({idna_test["input"]!r})' + comment.rstrip()
    )
    caplog.set_level(logging.INFO)

    encoded_input = _encode_host_ending_code_points(idna_test["input"])

    if idna_test["output"] is None:
        with pytest.raises(URLParseError):
            _ = URL(f"https://{encoded_input}/x")
    else:
        url = URL(f"https://{encoded_input}/x")
        assert url.host == idna_test["output"], msg
        assert url.hostname == idna_test["output"], msg
        assert url.pathname == "/x", msg
        assert url.href == f'https://{idna_test["output"]}/x', msg
