import logging
from ebclient.eb_consts import EBConsts
from ebclient.crypto_util import *
from ebclient.eb_request import RequestCall, RequestHolder
from ebclient.eb_utils import EBUtils
from errors import *
from registration import *
import requests


__author__ = 'dusanklinec'


logger = logging.getLogger(__name__)


class BaseRegistrationRequest(object):
    """
    Base request class for registration requests
    """
    def __init__(self, client_data=None, env=None, operation=None, config=None, *args, **kwargs):
        self.client_data = client_data
        self.config = config
        self.env = env
        self.operation = operation

        # Request & response
        self.request = None
        self.response = None
        self.caller = None
        pass

    def call(self, client_data=None, *args, **kwargs):
        """
        Calls the request with input data using given configuration (retry, timeout, ...).
        :param input_data:
        :param args:
        :param kwargs:
        :return:
        """
        self.build_request(client_data)
        self.caller = RequestCall(self.request)

        try:
            self.caller.call()
            self.response = self.caller.response

            if self.response is None:
                raise ValueError('Empty response')
            if self.response.response is None \
                    or 'response' not in self.response.response \
                    or self.response.response['response'] is None:
                raise ValueError('No result data')

            return self.response.response['response']

        except Exception as e:
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
            self.client_data = input_data
        if self.client_data is None:
            raise ValueError('Input data is None')

        self.request = RequestHolder()
        self.request.nonce = get_random_vector(EBConsts.FRESHNESS_NONCE_LEN)
        self.request.endpoint = self.config.endpoint_register
        self.request.url = self.config.endpoint_register.get_url() + "/api/v1/client"
        self.request.configuration = self.config
        self.request.api_method = self.operation
        self.request.headers = {'X-Auth-Token': 'public'}

        # Result request body
        self.request.body = {
            'nonce': to_hex(self.request.nonce),
            'version': 1,
            'function': self.operation,
            'environment': self.env if self.env is not None else ENVIRONMENT_DEVELOPMENT,
            'client': self.client_data
        }

        return self.request


class RegistrationRequest(BaseRegistrationRequest):
    """
    Class handles registration requests with the EB API
    """
    def __init__(self, client_data=None, env=None, config=None, *args, **kwargs):
        super(RegistrationRequest, self).__init__(
            client_data=client_data,
            env=env,
            operation=EBConsts.REQUEST_CREATE,
            config=config)


class ApiKeyRequest(BaseRegistrationRequest):
    """
    Class handles registration requests with the EB API
    """
    def __init__(self, client_data=None, endpoint=None, env=None, config=None, *args, **kwargs):
        super(ApiKeyRequest, self).__init__(
            client_data=client_data,
            env=env,
            operation=EBConsts.REQUEST_ADD_API,
            config=config)
        self.endpoint = endpoint

    def build_request(self, input_data=None, *args, **kwargs):
        req = super(ApiKeyRequest, self).build_request(input_data, *args, **kwargs)
        req.body['endpoint'] = self.endpoint
        return req

