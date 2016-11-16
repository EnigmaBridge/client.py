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
    CLIENT_SUFFIX = "/api/v1/client"
    API_KEY_SUFFIX = "/api/v1/apikey"

    """
    Base request class for hutx requests.
    (Registration, API key generation, domain enrollment)
    """
    def __init__(self, client_data=None, env=None, operation=None, config=None, api_data=None, aux_data=None,
                 url_suffix=None, *args, **kwargs):
        self.client_data = client_data
        self.api_data = api_data
        self.aux_data = aux_data
        self.config = config
        self.env = env
        self.operation = operation
        self.url_suffix = url_suffix if url_suffix is not None else self.CLIENT_SUFFIX

        # Request & response
        self.request = None
        self.response = None
        self.caller = None
        self.last_exception = None
        pass

    def try_call(self, client_data=None, api_data=None, aux_data=None, *args, **kwargs):
        """
        Calls the request catching all exceptions
        :param client_data:
        :param api_data:
        :param aux_data:
        :param args:
        :param kwargs:
        :return:
        """
        try:
            return self.call(client_data, api_data, aux_data, *args, **kwargs)
        except Exception as e:
            self.last_exception = e
        return None

    def call(self, client_data=None, api_data=None, aux_data=None, *args, **kwargs):
        """
        Calls the request with input data using given configuration (retry, timeout, ...).
        :param input_data:
        :param args:
        :param kwargs:
        :return:
        """
        self.build_request(client_data=client_data, api_data=api_data, aux_data=aux_data)
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
            raise
        pass

    def get_endpoint(self):
        return self.config.endpoint_register

    def extend_request(self, req):
        return req

    def build_request(self, input_data=None, api_data=None, aux_data=None, *args, **kwargs):
        """
        Builds request

        :param input_data:
        :param args:
        :param kwargs:
        :return:
        """
        if input_data is not None:
            self.client_data = input_data
        if api_data is not None:
            self.api_data = api_data
        if aux_data is not None:
            self.aux_data = aux_data

        self.request = RequestHolder()
        self.request.nonce = get_random_vector(EBConsts.FRESHNESS_NONCE_LEN)

        self.request.endpoint = self.get_endpoint()
        self.request.url = self.get_endpoint().get_url() + self.url_suffix

        self.request.configuration = self.config
        self.request.api_method = self.operation
        self.request.headers = {'X-Auth-Token': 'public'}

        # Result request body
        self.request.body = {
            'nonce': to_hex(self.request.nonce),
            'version': 1,
            'function': self.operation,
            'environment': self.env if self.env is not None else ENVIRONMENT_DEVELOPMENT,
        }

        if self.client_data is not None:
            self.request.body['client'] = self.client_data
        if self.api_data is not None:
            self.request.body['apidata'] = self.api_data
        if self.aux_data is not None:
            if isinstance(self.aux_data, types.DictionaryType):
                self.request.body = EBUtils.merge(self.request.body, self.aux_data)
            else:
                raise ValueError('Aux data has to be a dictionary')

        self.request = self.extend_request(self.request)
        return self.request


class GetClientAuthRequest(BaseRegistrationRequest):
    """
    This is a simple API call that returns the type of authentication required for a particular client type.
    """
    def __init__(self, client_data=None, env=None, config=None, *args, **kwargs):
        super(GetClientAuthRequest, self).__init__(
            client_data=client_data,
            env=env,
            operation=EBConsts.REQUEST_GET_AUTH,
            config=config)


class InitClientAuthRequest(BaseRegistrationRequest):
    """
    If registration of a new client requires the server to provide or initialize an authentication process,
    this API call will provide the server with all the necessary information.

    Response can be two-fold:
        - input for creating authentication data, if any;
        - requesting the server to use an alternative communication channel to provide the requestor with data out-of-band
    """

    def __init__(self, client_data=None, env=None, config=None, *args, **kwargs):
        super(InitClientAuthRequest, self).__init__(
            client_data=client_data,
            env=env,
            operation=EBConsts.REQUEST_INIT_AUTH,
            config=config)


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

    def extend_request(self, req):
        req.body['endpoint'] = self.endpoint
        return req


class ShowApiRequest(BaseRegistrationRequest):
    """
    Load info about API key
    """
    def __init__(self, client_data=None, api_data=None, env=None, config=None, *args, **kwargs):
        super(ShowApiRequest, self).__init__(
            client_data=client_data,
            api_data=api_data,
            env=env,
            operation=EBConsts.REQUEST_SHOW_API,
            config=config)


class ListOperationsRequest(BaseRegistrationRequest):
    """
    Lists allowed operations for the API key. Returns template requests for createUO.
    """
    def __init__(self, api_data=None, env=None, config=None, *args, **kwargs):
        super(ListOperationsRequest, self).__init__(
            api_data=api_data,
            env=env,
            operation=EBConsts.REQUEST_LIST_OPERATIONS,
            config=config,
            url_suffix=self.API_KEY_SUFFIX)


class EnrolDomainRequest(BaseRegistrationRequest):
    """
    Enrol a new domain name
    """
    def __init__(self, api_data=None, env=None, config=None, *args, **kwargs):
        super(EnrolDomainRequest, self).__init__(
            api_data=api_data,
            env=env,
            operation=EBConsts.REQUEST_ENROL_DOMAIN,
            config=config,
            url_suffix=self.API_KEY_SUFFIX)


class GetDomainChallengeRequest(BaseRegistrationRequest):
    """
    Get challenge for domain update
    """
    def __init__(self, api_data=None, env=None, config=None, *args, **kwargs):
        super(GetDomainChallengeRequest, self).__init__(
            api_data=api_data,
            env=env,
            operation=EBConsts.REQUEST_GET_DOMAIN_CHALLENGE,
            config=config,
            url_suffix=self.API_KEY_SUFFIX)


class UpdateDomainRequest(BaseRegistrationRequest):
    """
    Get challenge for domain update
    """
    def __init__(self, api_data=None, env=None, config=None, *args, **kwargs):
        super(UpdateDomainRequest, self).__init__(
            api_data=api_data,
            env=env,
            operation=EBConsts.REQUEST_UPDATE_DOMAIN,
            config=config,
            url_suffix=self.API_KEY_SUFFIX)


class InstallStatusRequest(BaseRegistrationRequest):
    """
    Get challenge for domain update
    """
    def __init__(self, api_data=None, status_data=None, env=None, config=None, *args, **kwargs):
        super(InstallStatusRequest, self).__init__(
            api_data=api_data,
            env=env,
            operation=EBConsts.REQUEST_INSTALL_STATUS,
            config=config,
            url_suffix=self.API_KEY_SUFFIX)

        if status_data is not None:
            if self.aux_data is None:
                self.aux_data = {}
            self.aux_data['statusdata'] = status_data


class UnlockDomainRequest(BaseRegistrationRequest):
    """
    Get challenge for domain update
    """
    def __init__(self, api_data=None, env=None, config=None, *args, **kwargs):
        super(UnlockDomainRequest, self).__init__(
            api_data=api_data,
            env=env,
            operation=EBConsts.REQUEST_UNLOCK_DOMAIN,
            config=config,
            url_suffix=self.API_KEY_SUFFIX)


