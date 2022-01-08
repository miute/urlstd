import json
from pathlib import Path

parent = Path(__file__).parent

with open(parent / "resources" / "setters_tests.json", "rb") as fp:
    setters_tests = json.load(fp)
    del setters_tests["comment"]

with open(parent / "resources" / "toascii.json", "rb") as fp:
    res = json.load(fp)
    toascii = [x for x in res if isinstance(x, dict)]

with open(parent / "resources" / "urltestdata.json", "rb") as fp:
    res = json.load(fp)
    urltestdata = [x for x in res if isinstance(x, dict)]

del parent, res
