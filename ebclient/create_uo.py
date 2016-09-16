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

    
