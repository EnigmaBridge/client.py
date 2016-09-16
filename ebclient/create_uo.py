import logging
import types
from eb_utils import EBUtils
from eb_consts import EBConsts
from eb_request import *
from uo import *
from crypto_util import *
from errors import *
import json
from create_uo import Gen
from create_uo import TemplateFields
from create_uo import Environment
from create_uo import KeyTypes
from eb_consts import UOTypes


__author__ = 'dusanklinec'


logger = logging.getLogger(__name__)


class CreateUO:

    @staticmethod
    def get_default_template():
        """
        Returns default getTemplate request specification.
        :return:
        """
        return {
            "format": 1,
            "protocol": 1,
            "environment": Environment.DEV, # shows whether the UO should be for production (live), test (pre-production testing), or dev (development)
            "maxtps": "unlimited", # maximum guaranteed TPS
            "core": "empty", # how many cards have UO loaded permanently
            "persistence": "one_minute", # once loaded onto card, how long will the UO stay there without use (this excludes the "core")
            "priority": "default", # this defines a) priority when the server capacity is fully utilised and it also defines how quickly new copies of UO are installed (pre-empting icreasing demand)
            "separation": "time", # "complete" = only one UO can be loaded on a smartcard at one one time
            "bcr": TemplateFields.yes, # "yes" will ensure the UO is replicated to provide high availability for any possible service disruption
            "unlimited": TemplateFields.yes, #  if "yes", we expect the data starts with an IV to initialize decryption of data - this is for communication security
            "clientiv": TemplateFields.yes, # if "yes", we expect the data starting with a diversification 16B for communication keys
            "clientdiv": TemplateFields.no,
            "resource": "global",
            "credit": 32677, # <1-32767>, a limit a seed card can provide to the EB service

            TemplateFields.generation: {
                TemplateFields.commkey: Gen.CLIENT,
                TemplateFields.billingkey: Gen.LEGACY_RANDOM,
                TemplateFields.appkey: Gen.LEGACY_RANDOM
            }
        }

    @staticmethod
    def get_template_request_spec(spec):
        """
        Returns get template request specification, using default values if not present in spec.
        If dictionary is provided, it is considered as JSON.
        If Configuration is provided, we look at createTpl object
        :param spec:
        :return:
        """
        dst = CreateUO.get_default_template()
        src = None
        if isinstance(spec, Configuration):
            src = spec.create_tpl
        elif isinstance(spec, types.DictType):
            src = spec
        else:
            raise ValueError('Unrecognized spec type')

        if spec is not None:
            dst = EBUtils.merge(dst, spec)

        return dst

    @staticmethod
    def set_type(spec, type):
        """
        Updates type integer in the cerate UO specification.
        Type has to already have generations flags set correctly.
        Generation field is set accordingly
        :param spec:
        :param type:
        :return:
        """
        spec[TemplateFields.generation][TemplateFields.commkey] = \
            Gen.CLIENT if (type & (1L << TemplateFields.FLAG_COMM_GEN)) > 0 else Gen.LEGACY_RANDOM
        spec[TemplateFields.generation][TemplateFields.appkey] = \
            Gen.CLIENT if (type & (1L << TemplateFields.FLAG_APP_GEN)) > 0 else Gen.LEGACY_RANDOM
        spec[TemplateFields.type] = "%x" % type
        return spec

    @staticmethod
    def get_rsa_type(bitsize):
        if bitsize == 1024:
            return UOTypes.RSA1024DECRYPT_NOPAD
        elif bitsize == 2048:
            return UOTypes.RSA2048DECRYPT_NOPAD
        else:
            raise ValueError('Unrecognized RSA type: %d bits' % bitsize)

    @staticmethod
    def get_template_request(configuration, spec):
        """
        Builds API request block.
        :param configuration:
        :param spec:
        :return:
        """
        req = RequestHolder()
        req.api_method = 'GetUserObjectTemplate'
        req.nonce = EBUtils.generate_nonce()
        req.api_object = EBUtils.build_api_object(api_key=configuration.api_key, uo_id=0x1)
        req.body = {"data": spec}
        req.configuration = configuration
        req.endpoint = configuration.endpoint_enroll
        return req

    @staticmethod
    def template_request(configuration, spec):
        """
        Calls the get template request

        :param configuration:
        :param spec:
        :return:
        """
        # Template request, nonce will be regenerated.
        req = CreateUO.get_template_request(configuration, spec)

        # Do the request with retry.
        caller = RequestCall(req)
        resp = caller.call()
        return resp


class TemplateKey(object):
    """
    Simple class represents key to be set to the template
    """
    def __init__(self, type=None, key=None, *args, **kwargs):
        self.type = type
        self.key = key


class TemplateProcessor(object):
    """
    Processes input template
     - fills in the keys
     - sets flags accordingly
     - encrypts
    """
    def __init__(self, configuration=None, keys=None, template=None, *args, **kwargs):
        self.config = configuration
        self.keys = keys
        self.template = template

        # Processing
        self.tpl_buff = None

    def process(self, template):
        if template is not None:
            self.template = template

        self.validate(self.template)

        self.tpl_buff = from_hex(self.template['result']['template'])

        self.fill_in_keys()

        self.set_flags()


        pass

    def validate(self, template):
        if template is None \
                or 'result' not in template \
                or 'encryptionoffset' not in template['result'] \
                or 'flagoffset' not in template['result'] \
                or 'keyoffsets' not in template['result'] \
                or 'importkeys' not in template['result'] \
                or 'template' not in template['result'] \
                or 'objectid' not in template['result']:
            raise InvalidResponse('Invalid template object')

    def fill_in_keys(self):
        if self.keys is None:
            self.keys = {}

        # Generate comm keys if not present
        if KeyTypes.COMM_ENC not in self.keys:
            self.keys[KeyTypes.COMM_ENC] = TemplateKey(type=KeyTypes.COMM_ENC, key=get_random_vector(EBConsts.COMM_ENC_KEY_LENGTH))
        if KeyTypes.COMM_MAC not in self.keys:
            self.keys[KeyTypes.COMM_MAC] = TemplateKey(type=KeyTypes.COMM_MAC, key=get_random_vector(EBConsts.COMM_MAC_KEY_LENGTH))

        tpl = self.template['result']
        key_offsets = tpl['keyoffsets']
        for offset in key_offsets:
            if offset is None \
                    or 'type' not in offset \
                    or 'length' not in offset \
                    or 'offset' not in offset:
                logger.info("Invalid offset: %s", offset)
                continue

            key_type = offset['type']
            if key_type in self.keys:
                c_key = self.keys[key_type]
                c_len_bits = offset['length']
                c_off_bits = offset['offset']

                if len(c_key.key) * 8 != c_len_bits:
                    logger.info("Key length mismatch for key: %s", key_type)
                    continue

                self.tpl_buff = bytes_replace(self.tpl_buff,
                                              c_off_bits / 8,
                                              (c_off_bits + c_len_bits) / 8,
                                              c_key.key)
            pass
        pass

    def set_flags(self):
        """
        Set flags representing generation way accordingly - commkeys are client generated, app key is server generated.
        :return:
        """
        tpl = self.template['result']
        offset = tpl['flagoffset']/8

        # comm keys provided?
        bytes_transform(self.tpl_buff, offset+1, offset+2, lambda x: self.set_flag_bit(x))

    def set_flag_bit(self, x):
        """
        Function internally used in set_flags. No multi-line lambdas in python :/
        :param x:
        :return:
        """
        if KeyTypes.COMM_ENC in self.keys:
            x &= ~0x8
        if KeyTypes.APP_KEY in self.keys:
            x &= ~0x10
        return x

    