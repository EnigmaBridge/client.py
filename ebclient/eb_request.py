import logging
from eb_utils import EBUtils
from eb_consts import EBConsts
from crypto_util import *
from errors import *
from uo import *
import requests

__author__ = 'dusanklinec'


logger = logging.getLogger(__name__)


class RequestHolder(object):
    """
    Class holding the general request
    """
    def __init__(self, body=None, api_object=None, nonce=None, endpoint=None, config=None, *args, **kwargs):
        self.body = body
        self.api_object = api_object
        self.api_method = 'ProcessData'
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


class RequestCall(object):
    """
    Class responsible for making a request on the EB API according to the configuration.
    """

    def __init__(self, request=None, *args, **kwargs):
        self.request = request
        self.response = None
        self.last_resp = None
        pass

    def call(self, request=None, *args, **kwargs):
        """
        Calls multiple time - with retry.

        :param request:
        :return: response
        """
        if request is not None:
            self.request = request

        retry = self.request.configuration.retry
        if not isinstance(retry, SimpleRetry):
            raise Error('Currently only the fast retry is supported')

        last_exception = None
        for i in range(0, retry.maxRetry):
            try:
                self.call_once()
                return self.response

            except Exception as ex:
                last_exception = ex
                logger.debug("Request %d failed, exceptionL %s", i, ex)

        raise RequestFailed(last_exception)

    def call_once(self, request=None, *args, **kwargs):
        """
        Performs one API request.
        Raises exception on failure.

        :param request:
        :param args:
        :param kwargs:
        :return: response
        """
        if request is not None:
            self.request = request

        config = self.request.configuration
        if config.http_method != EBConsts.HTTP_METHOD_POST or config.method != EBConsts.METHOD_REST:
            raise Error('Not implemented yet, only REST POST method is allowed')

        # Construct URL
        # e.g.,: http://site2.enigmabridge.com:12000/1.0/testAPI/GetAllAPIKeys/abcdef012345
        url = "%s/1.0/%s/%s/%s" % (
            self.request.endpoint.get_url(),
            self.request.api_object,
            self.request.api_method,
            to_hex(self.request.nonce)
        )
        logger.info("URL to call: %s", url)

        # Do the request
        resp = requests.post(url, json=self.request.body, timeout=config.timeout)
        self.last_resp = resp

        # For successful API call, response code will be 200 (OK)
        if resp.ok:
            json = resp.json()
            self.response = ResponseHolder()
            self.response.response = json

            # Check the code
            if not 'status' in json:
                raise InvalidResponse('No status field')

            self.response.status = from_hex(json['status'])
            if self.response.status != EBConsts.STATUS_OK:
                raise InvalidStatus('Status is %s' % json['statusdetail'])

            return self.response

        else:
            # If response code is not ok (200), print the resulting http error code with description
            resp.raise_for_status()
        pass
