__author__ = 'dusanklinec'

import sys


if sys.version_info[0] == 2:
    def import_urlparse():
        global urlparse
        from urlparse import urlparse

else:
    def import_urlparse():
        global urlparse
        from urllib.parse import urlparse


def parse_url(url):
    if 'urlparse' not in globals() or urlparse is None:
        import_urlparse()
    return urlparse(url)