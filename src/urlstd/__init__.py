"""
Python implementation of the WHATWG URL Standard
"""

from logging import NullHandler, getLogger

getLogger(__name__).addHandler(NullHandler())
del NullHandler, getLogger
