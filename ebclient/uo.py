#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import re
import time
from eb_consts import EBConsts
from crypto_util import *
from eb_configuration import *
from py3compat import *

__author__ = 'dusanklinec'


logger = logging.getLogger(__name__)


class UO(object):
    """
    User object representation.
    """
    def __init__(self, uo_id=-1, uo_type=-1, enc_key=None, mac_key=None, api_key=None, endpoint=None, configuration=None, *args, **kwargs):
        self.uo_id = uo_id
        self.uo_type = uo_type
        self.enc_key = enc_key
        self.mac_key = mac_key

        self.api_key = api_key
        self.endpoint = endpoint
        self.configuration = configuration

    def resolve_api_key(self):
        if self.api_key is not None:
            return self.api_key
        elif self.configuration is not None:
            return self.configuration.api_key
        else:
            return None

    def resolve_endpoint(self):
        if self.endpoint is not None:
            return self.endpoint
        elif self.configuration is not None:
            return self.configuration.endpoint_process
        else:
            return None

    def __repr__(self):
        return '%s(uo_id=%r, uo_type=%r, enc_key=%r, mac_key=%r, api_key=%r, endpoint=%r, configuration=%r)' \
               % (self.__class__, self.uo_id, self.uo_type, self.enc_key, self.mac_key, self.api_key, self.endpoint,
                  self.configuration)

    def __str__(self):
        return 'UO(uo_id=%r, uo_type=%r, api_key=%r, endpoint=%r)' \
               % (self.uo_id, self.uo_type, self.api_key, self.endpoint)


class RSAPrivateKey(object):
    """
    Contains UO and RSA modulus and exponent
    """
    def __init__(self, uo=None, n=None, e=None, *args, **kwargs):
        self.uo = uo
        self.n = n
        self.e = e

