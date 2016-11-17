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
        self.url = None
        self.headers = None
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

    def __init__(self, request=None, response_checker=None, *args, **kwargs):
        self.request = request
        self.response = None
        self.last_resp = None
        self.response_checker = response_checker
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
        for i in range(0, retry.max_retry):
            try:
                if i > 0:
                    retry.sleep_jitter()

                self.call_once()
                return self.response

            except Exception as ex:
                last_exception = ex
                logger.debug("Request %d failed, exceptionL %s", i, ex)

        raise RequestFailed(last_exception)

    @staticmethod
    def field_to_long(value):
        """
        Converts given value to long if possible, otherwise None is returned.

        :param value:
        :return:
        """
        if isinstance(value, (types.LongType, types.IntType)):
            return long(value)
        elif isinstance(value, basestring):
            return bytes_to_long(from_hex(value))
        else:
            return None

    def build_url(self):
        """
        Construct URL
        e.g.,: http://site2.enigmabridge.com:12000/1.0/testAPI/GetAllAPIKeys/abcdef012345

        :return:
        """
        url = "%s/1.0/%s/%s/%s" % (
            self.request.endpoint.get_url(),
            self.request.api_object,
            self.request.api_method,
            to_hex(self.request.nonce)
        )
        return url

    @staticmethod
    def get_text_status(json):
        """
        Extracts textual status from the response - statusdetail, if present.
        Otherwise extracts status field.

        :param json:
        :return:
        """
        if json is None:
            return None
        elif 'statusdetail' in json:
            return json['statusdetail']
        elif 'status' in json:
            return json['status']
        else:
            return None

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

        url = self.request.url if self.request.url is not None else self.build_url()
        logger.debug("URL to call: %s", url)

        # Do the request
        resp = requests.post(url, json=self.request.body, timeout=config.timeout, headers=self.request.headers)
        self.last_resp = resp
        return self.check_response(resp)

    def check_response(self, resp):
        """
        Checks response after request was made.
        Checks status of the response, mainly

        :param resp:
        :return:
        """

        # For successful API call, response code will be 200 (OK)
        if resp.ok:
            json = resp.json()
            self.response = ResponseHolder()
            self.response.response = json

            # Check the code
            if 'status' not in json:
                raise InvalidResponse('No status field')

            self.response.status = self.field_to_long(json['status'])
            if self.response.status != EBConsts.STATUS_OK:
                txt_status = self.get_text_status(json)
                raise InvalidStatus('Status is %s (%04X)'
                                    % (txt_status if txt_status is not None else "", self.response.status))

            if self.response_checker is not None:
                self.response_checker(self.response)

            return self.response

        else:
            # If response code is not ok (200), print the resulting http error code with description
            resp.raise_for_status()
        pass
