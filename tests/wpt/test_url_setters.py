# References:
#  https://github.com/web-platform-tests/wpt/blob/master/url/url-setters.any.js

import logging

import pytest

from urlstd.error import URLParseError
from urlstd.parse import URL

from . import setters_tests

all_test_cases = [(k, v) for k in setters_tests for v in setters_tests[k]]


@pytest.mark.parametrize(("attribute_to_be_set", "test_case"), all_test_cases)
def test_setter(attribute_to_be_set, test_case, caplog):
    caplog.set_level(logging.INFO)
    name = "Setting <{href}>.{attribute_to_be_set} = {new_value!r}".format(
        href=test_case["href"],
        attribute_to_be_set=attribute_to_be_set,
        new_value=test_case["new_value"],
    )
    if "comment" in test_case:
        name += " " + test_case["comment"]
    test_setter.__doc__ = msg = "URL: " + name
    url = URL(test_case["href"])
    try:
        setattr(url, attribute_to_be_set, test_case["new_value"])
    except URLParseError:
        pass
    for attribute in test_case["expected"]:
        assert getattr(url, attribute) == test_case["expected"][attribute], msg
