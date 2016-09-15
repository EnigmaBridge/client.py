import logging
from eb_utils import EBUtils
from eb_consts import EBConsts
from crypto_util import *
from uo import *

__author__ = 'dusanklinec'


logger = logging.getLogger(__name__)


class RequestHolder(object):
    def __init__(self, body=None, api_object=None, nonce=None, endpoint=None, config=None, *args, **kwargs):
        self.body = body
        self.api_object = api_object
        self.nonce = nonce
        self.endpoint = endpoint
        self.configuration = config
        pass


class ResponseHolder(object):
    def __init__(self, *args, **kwargs):
        self.response = None

        self.status = 0x0
        self.object_id = -1
        self.nonce = None
        self.decrypted = None
        pass
    pass

