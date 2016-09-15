import logging
from eb_utils import EBUtils
from eb_consts import EBConsts
from crypto_util import *
from uo import *

__author__ = 'dusanklinec'


logger = logging.getLogger(__name__)


class RequestHolder(object):
    """
    Class holding the general request
    """
    def __init__(self, body=None, api_object=None, nonce=None, endpoint=None, config=None, *args, **kwargs):
        self.body = body
        self.api_object = api_object
        self.nonce = nonce
        self.endpoint = endpoint
        self.configuration = config
        pass


class ResponseHolder(object):
    """
    Class holding the general response
    """
    def __init__(self, *args, **kwargs):
        self.response = None
        self.status = 0x0
        pass
    pass

