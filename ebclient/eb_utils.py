#!/usr/bin/env python
# -*- coding: utf-8 -*-

from ebclient.eb_consts import EBConsts
from ebclient.crypto_util import *
from ebclient.uo import UO
if sys.version_info[0] >= 3:
    from past.builtins import long

__author__ = 'Enigma Bridge Ltd'


logger = logging.getLogger(__name__)


class Switch(object):
    """
    Switch implementation
    http://code.activestate.com/recipes/410692/
    """
    def __init__(self, value):
        self.value = value
        self.fall = False

    def __iter__(self):
        """Return the match method once, then stop"""
        yield self.match
        raise StopIteration

    def match(self, *args):
        """Indicate whether or not to enter a case suite"""
        if self.fall or not args:
            return True
        elif self.value in args:  # changed for v1.5, see below
            self.fall = True
            return True
        else:
            return False


class EBUtils(object):
    """
    Minor EB client utils
    """

    @staticmethod
    def build_api_object(uo=None, api_key=None, uo_id=None, uo_type=None):
        """
        Builds API object identifier
        :return:
        """
        if uo is not None:
            api_key = uo.resolve_api_key() if uo.resolve_api_key() is not None else api_key
            uo_id = uo.uo_id if uo.uo_id is not None else uo_id
            uo_type = uo.uo_type if uo.uo_type is not None else uo_type

        if uo_type is None or uo_type == EBConsts.INVALID_KEY_TYPE:
            uo_type = 0

        return "%s%010x%010x" % (api_key, uo_id, uo_type)

    @staticmethod
    def get_request_type(type_in):
        """
        Constructs request type string for ProcessData packet from the UOtype of UO object
        :param type_in:
        :return:
        """
        uo_type = None
        if isinstance(type_in, (int, long)):
            uo_type = int(type_in)
        elif isinstance(type_in, UO):
            uo_type = type_in.uo_type
        return EBConsts.REQUEST_TYPES.get(uo_type, 'PROCESS')

    @staticmethod
    def generate_nonce():
        """
        Generates a random nonce of the standard length for EB API requests
        :return:
        """
        return get_random_vector(EBConsts.FRESHNESS_NONCE_LEN)

    @staticmethod
    def demangle_nonce(nonce):
        """
        Demangles nonce returned in process data response
        :param nonce:
        :type nonce: bytes
        :return:
        """
        return to_bytes(bytearray(nonce))

    @staticmethod
    def merge(final, update, path=None):
        """
        Deep merges dictionary object b into a.
        :param final:
        :param update:
        :param path: 
        :return:
        """
        if final is None:
            return None
        if update is None:
            return final
        if path is None:
            path = []

        for key in update:
            if key in final:
                if isinstance(final[key], dict) and isinstance(update[key], dict):
                    EBUtils.merge(final[key], update[key], path + [str(key)])
                elif final[key] == update[key]:
                    pass  # same leaf value
                else:
                    raise ValueError('Conflict at %s' % '.'.join(path + [str(key)]))
            else:
                final[key] = update[key]
        return final

    @staticmethod
    def update(dest, variation, path=None):
        """
        Deep merges dictionary object variation into dest, dest keys in variation will be assigned new values
        from variation
        :param dest:
        :param variation:
        :param path:
        :return:
        """
        if dest is None:
            return None
        if variation is None:
            return dest
        if path is None:
            path = []

        for key in variation:
            if key in dest:
                if isinstance(dest[key], dict) and isinstance(variation[key], dict):
                    EBUtils.update(dest[key], variation[key], path + [str(key)])
                elif dest[key] == variation[key]:
                    pass  # same leaf value
                else:
                    dest[key] = variation[key]
            else:
                dest[key] = variation[key]

        return dest
