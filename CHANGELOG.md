# Changelog

## v2023.7.26.dev1 / WIP

Implement latest specifications of the [URL Living Standard](https://url.spec.whatwg.org/commit-snapshots/fff33c343f01575c691bba6cdeeefb9d09e792a9/).

- ADDED
  - Add `URL.can_parse()`
  - Add `URL.__eq__()` and `URL.equals()`
  - Add `URLRecord.__eq__()` and `URLRecord.equals()`
  - Add `URLSearchParams.__eq__()`
  - Add `URLSearchParams.__getitem__()`
  - Add `IDNA.domain_to_unicode()`
- FIXED
  - Fix improper handling of the `VerifyDnsLength` flag in `IDNA.domain_to_ascii()`
  - Fix incorrect domain length in `IDNA.domain_to_ascii()`
  - Fix `parse_url()` treats `base=""` as `base=None`
- IMPROVED
  - Change Python type hints to a new style
  - Update validation error message
  - Change arguments of `URLSearchParams.delete()`
    - NEW: `delete(name: str, value: Optional[str | int | float] = None)`
    - OLD: `delete(name: str)`
  - Change arguments of `URLSearchParams.has()`
    - NEW: `has(name: str, value: Optional[str | int | float] = None)`
    - OLD: `has(name: str)`
  - Change arguments of `parse_url()`
    - NEW: `parse_url(urlstring: str, base: Optional[str | URLRecord] = None, encoding: str = "utf-8")`
    - OLD: `parse_url(urlstring: str, base: Optional[str] = None, encoding: str = "utf-8")`
- REMOVED
  - Drop support for Python 3.7

## v2021.10.25.post2 / 2022-11-19

- ADDED
  - Add support for Python 3.11
- FIXED
  - Fix Python type hints

## v2021.10.25.post1 / 2022-05-06

- IMPROVED
  - Update docstring

## v2021.10.25 / 2022-02-01

Initial release (based on commit [f787850](https://url.spec.whatwg.org/commit-snapshots/f787850695969d51caaa5c290f2c2e050e083638/) of the [URL Living Standard](https://url.spec.whatwg.org/)).

## v2021.10.25.dev1 / 2022-01-08

Pre-release.
