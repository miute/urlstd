# References:
#  https://github.com/web-platform-tests/wpt/blob/master/url/urlsearchparams-stringifier.any.js

from urlstd.parse import URL, URLSearchParams


def test_serialize_space():
    """Serialize space."""
    params = URLSearchParams()
    params.append("a", "b c")
    assert params + "" == "a=b+c"
    params.delete("a")
    params.append("a b", "c")
    assert params + "" == "a+b=c"


def test_serialize_empty_value():
    """Serialize empty value."""
    params = URLSearchParams()
    params.append("a", "")
    assert params + "" == "a="
    params.append("a", "")
    assert params + "" == "a=&a="
    params.append("", "b")
    assert params + "" == "a=&a=&=b"
    params.append("", "")
    assert params + "" == "a=&a=&=b&="
    params.append("", "")
    assert params + "" == "a=&a=&=b&=&="


def test_serialize_empty_name():
    """Serialize empty name."""
    params = URLSearchParams()
    params.append("", "b")
    assert params + "" == "=b"
    params.append("", "b")
    assert params + "" == "=b&=b"


def test_serialize_empty_name_and_value():
    """Serialize empty name and value."""
    params = URLSearchParams()
    params.append("", "")
    assert params + "" == "="
    params.append("", "")
    assert params + "" == "=&="


def test_serialize_plus():
    """Serialize +"""
    params = URLSearchParams()
    params.append("a", "b+c")
    assert params + "" == "a=b%2Bc"
    params.delete("a")
    params.append("a+b", "c")
    assert params + "" == "a%2Bb=c"


def test_serialize_equal():
    """Serialize ="""
    params = URLSearchParams()
    params.append("=", "a")
    assert params + "" == "%3D=a"
    params.append("b", "=")
    assert params + "" == "%3D=a&b=%3D"


def test_serialize_ampersand():
    """Serialize &"""
    params = URLSearchParams()
    params.append("&", "a")
    assert params + "" == "%26=a"
    params.append("b", "&")
    assert params + "" == "%26=a&b=%26"


def test_serialize_safe_characters():
    """Serialize *-._"""
    params = URLSearchParams()
    params.append("a", "*-._")
    assert params + "" == "a=*-._"
    params.delete("a")
    params.append("*-._", "c")
    assert params + "" == "*-._=c"


def test_serialize_percent():
    """Serialize %"""
    params = URLSearchParams()
    params.append("a", "b%c")
    assert params + "" == "a=b%25c"
    params.delete("a")
    params.append("a%b", "c")
    assert params + "" == "a%25b=c"

    params = URLSearchParams("id=0&value=%")
    assert params + "" == "id=0&value=%25"


def test_serialize_00():
    """Serialize \\0"""
    params = URLSearchParams()
    params.append("a", "b\0c")
    assert params + "" == "a=b%00c"
    params.delete("a")
    params.append("a\0b", "c")
    assert params + "" == "a%00b=c"


def test_serialize_d83d_dca9():
    """Serialize \\uD83D\\uDCA9"""
    params = URLSearchParams()
    params.append("a", "b\uD83D\uDCA9c")
    assert params + "" == "a=b%F0%9F%92%A9c"
    params.delete("a")
    params.append("a\uD83D\uDCA9b", "c")
    assert params + "" == "a%F0%9F%92%A9b=c"


def test_urlsearchparams_tostring():
    """URLSearchParams.toString."""
    params = URLSearchParams("a=b&c=d&&e&&")
    assert str(params) == "a=b&c=d&e="
    params = URLSearchParams("a = b &a=b&c=d%20")
    assert str(params) == "a+=+b+&a=b&c=d+"

    params = URLSearchParams("a=&a=b")
    assert str(params) == "a=&a=b"

    params = URLSearchParams("b=%2sf%2a")
    assert str(params) == "b=%252sf*"

    params = URLSearchParams("b=%2%2af%2a")
    assert str(params) == "b=%252*f*"

    params = URLSearchParams("b=%%2a")
    assert str(params) == "b=%25*"


def test_urlsearchparams_connected_to_url():
    """URLSearchParams connected to URL."""
    url = URL("http://www.example.com/?a=b,c")
    params = url.search_params

    assert str(url) == "http://www.example.com/?a=b,c"
    assert str(params) == "a=b%2Cc"

    params.append("x", "y")

    assert str(url) == "http://www.example.com/?a=b%2Cc&x=y"
    assert str(params) == "a=b%2Cc&x=y"


def test_urlsearchparams_must_not_do_newline_normalization():
    """URLSearchParams must not do newline normalization."""
    url = URL("http://www.example.com/")
    params = url.search_params

    params.append("a\nb", "c\rd")
    params.append("e\n\rf", "g\r\nh")

    assert str(params) == "a%0Ab=c%0Dd&e%0A%0Df=g%0D%0Ah"
