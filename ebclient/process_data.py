import logging
from eb_utils import EBUtils
from eb_consts import EBConsts
from eb_request import *
from uo import *
from crypto_util import *
from errors import *

__author__ = 'dusanklinec'


logger = logging.getLogger(__name__)


class ProcessData(object):
    def __init__(self, uo=None, input_data=None, config=None, *args, **kwargs):
        self.uo = uo
        self.input_data = input_data
        self.configuration = config

        # Request & response
        self.request = None
        self.response = None
        self.caller = None

        # Call results
        self.decrypted = None
        self.resp_nonce = None
        self.resp_object_id = None
        self.exception = None

    def call(self, input_data=None, *args, **kwargs):
        """
        Calls the request with input data using given configuration (retry, timeout, ...).
        :param input_data:
        :param args:
        :param kwargs:
        :return:
        """
        self.build_request(input_data)
        self.caller = RequestCall(self.request)
        self.exception = None

        try:
            self.caller.call()
            self.response = self.caller.response
            self.decrypt_result()
            return self.decrypted

        except Exception as e:
            self.exception = e
            logger.info("Exception throw %s", e)
        pass

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

        self.request = RequestHolder()
        self.request.nonce = get_random_vector(EBConsts.FRESHNESS_NONCE_LEN)
        self.request.api_object = EBUtils.build_api_object(self.uo)
        self.request.endpoint = self.uo.resolve_endpoint()
        self.request.configuration = self.configuration
        self.request.api_method = EBConsts.REQUEST_PROCESS_DATA

        # Build plaintext plain_buffer
        plain_buffer = "\x1f%s%s%s" % (to_bytes(self.uo.uo_id, 4),
                                       to_bytes(self.request.nonce, EBConsts.FRESHNESS_NONCE_LEN),
                                       to_bytes(self.input_data))
        plain_buffer = PKCS7.pad(plain_buffer)

        # Encrypt-then-mac
        ciphertext = aes_enc(self.uo.enc_key, plain_buffer)
        mac = cbc_mac(self.uo.mac_key, ciphertext)

        # Result request body
        self.request.body = {"data":"Packet0_%s_0000%s" % (EBUtils.get_request_type(self.uo), to_hex(ciphertext + mac))}
        return self.request

    def decrypt_result(self, *args, **kwargs):
        """
        Decrypts ProcessData result with comm keys

        :param args:
        :param kwargs:
        :return:
        """
        if self.response is None:
            raise ValueError('Empty response')
        if self.response.response is None \
                or 'result' not in self.response.response \
                or self.response.response['result'] is None:
            raise ValueError('No result data')

        res_hex = self.response.response['result']

        # Strip out the plaintext part
        plain_length = bytes_to_long(from_hex(res_hex[0:4]))
        if plain_length > 0:
            res_hex = res_hex[4+plain_length:]
        else:
            res_hex = res_hex[4:]

        # Optionally strip trailing _... string
        idx_trail = res_hex.find('_')
        if idx_trail != -1:
            res_hex = res_hex[0:idx_trail]

        # Decode hex coding
        res_bytes = from_hex(res_hex)

        # Crypto stuff - check the length & padding
        if len(res_bytes) < 16:
            raise InvalidResponse('Result too short')

        mac_given = res_bytes[-16:]
        res_bytes = res_bytes[:-16]

        # Check the MAC
        mac_computed = cbc_mac(self.uo.mac_key, res_bytes)
        if not str_equals(mac_given, mac_computed):
            raise CryptoError('MAC invalid')

        # Decrypt
        decrypted = aes_dec(self.uo.enc_key, res_bytes)
        if len(decrypted) < 1+4+8 or decrypted[0:1] != bchr(0xf1):
            raise InvalidResponse('Invalid format')

        self.resp_object_id = bytes_to_long(decrypted[1:5])
        self.resp_nonce = EBUtils.demangle_nonce(decrypted[5:5+EBConsts.FRESHNESS_NONCE_LEN])
        self.decrypted = decrypted[5+EBConsts.FRESHNESS_NONCE_LEN:]
        self.decrypted = PKCS7.unpad(self.decrypted)
        return self.response

