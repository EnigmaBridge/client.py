#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = 'Enigma Bridge Ltd'

import sys

if sys.version_info[0] == 2:
    def import_urlparse():
        # noinspection PyGlobalUndefined
        global urlparse
        # noinspection PyGlobalUndefined
        from urlparse import urlparse

else:
    def import_urlparse():
        global urlparse
        from urllib.parse import urlparse


def parse_url(url):
    if 'urlparse' not in globals() or urlparse is None:
        import_urlparse()
    return urlparse(url)