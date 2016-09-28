import logging
import types
from eb_consts import EBConsts
from ebclient.crypto_util import *
from uo import UO

__author__ = 'dusanklinec'


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
        elif self.value in args: # changed for v1.5, see below
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
    def get_request_type(type):
        """
        Constructs request type string for ProcessData packet from the UOtype of UO object
        :param type:
        :return:
        """
        uo_type = None
        if isinstance(type, (types.IntType, types.LongType)):
            uo_type = int(type)
        elif isinstance(type, UO):
            uo_type = type.uo_type
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
        :return:
        """
        return to_bytes([chr((ord(y)-1) & 0xff) for y in nonce])

    @staticmethod
    def merge(a, b, path=None):
        """
        Deep merges dictionary object b into a.
        :param a:
        :param b:
        :return:
        """
        if a is None: return None
        if b is None: return a

        if path is None: path = []
        for key in b:
            if key in a:
                if isinstance(a[key], dict) and isinstance(b[key], dict):
                    EBUtils.merge(a[key], b[key], path + [str(key)])
                elif a[key] == b[key]:
                    pass # same leaf value
                else:
                    raise ValueError('Conflict at %s' % '.'.join(path + [str(key)]))
            else:
                a[key] = b[key]
        return a
