import logging
from eb_utils import EBUtils
from eb_consts import EBConsts
from crypto_util import *

__author__ = 'dusanklinec'


logger = logging.getLogger(__name__)


class ProcessData(object):
    def __init__(self, uo=None, input_data=None, nonce=None, request_type=None, *args, **kwargs):
        self.uo = uo
        self.input_data = input_data
        self.nonce = nonce
        self.request_type = request_type

        # Request building part
        self._object_id = None
        self._request_body = None

    def build_request(self, input_data=None, *args, **kwargs):
        """
        Builds request
        :param input_data:
        :param args:
        :param kwargs:
        :return:
        """
        if input_data is not None:
            self.input_data = input_data
        if self.input_data is None:
            raise ValueError('Input data is None')
        if self.uo is None:
            raise ValueError('UO is None')

        self._object_id = EBUtils.build_api_object(self.uo)
        if self.nonce is None:
            self.nonce = get_random_vector(EBConsts.FRESHNESS_NONCE_LEN)

        # Build plaintext buffer
        buffer = "\x1f%s%s%s" % (to_bytes(self.uo.uo_id, 4),
                                 to_bytes(self.nonce, EBConsts.FRESHNESS_NONCE_LEN),
                                 to_bytes(self.input_data))

        # Encrypt-then-mac
        ciphertext = aes_enc(self.uo.enc_key, PKCS7.pad(buffer))
        mac = cbc_mac(self.uo.mac_key, ciphertext)

        # Result request body
        self._request_body = "Packet0_%s_0000%s" % (EBUtils.get_request_type(self.uo), to_hex(ciphertext + mac))



