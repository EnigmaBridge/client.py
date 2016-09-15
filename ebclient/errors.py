__author__ = 'dusanklinec'


class Error(Exception):
    """Generic EB client error."""


class CryptoError(Error):
    """MAC invalid, ..."""

class InvalidResponse(Error):
    """Invalid server response"""

