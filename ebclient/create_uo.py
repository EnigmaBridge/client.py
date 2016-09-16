import logging
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


__author__ = 'dusanklinec'


logger = logging.getLogger(__name__)


class CreateUO:
    @staticmethod
    def getDefaultTemplate():
        """
        Generates default createUO template.
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



