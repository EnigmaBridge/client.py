import logging
import re
import time
from eb_utils import EBUtils
from eb_consts import EBConsts
from crypto_util import *
from py3compat import *

__author__ = 'dusanklinec'


logger = logging.getLogger(__name__)


class Endpoint(object):
    DEFAULT_SCHEME = 'https'
    DEFAULT_HOST = 'site2.enigmabridge.com'
    DEFAULT_PORT = 11180

    def __init__(self, scheme=DEFAULT_SCHEME, host=DEFAULT_HOST, port=DEFAULT_PORT, *args, **kwargs):
        self.scheme = scheme
        self.host = host
        self.port = port

    @classmethod
    def url(cls, url):
        o = parse_url(url)
        hostport = o.netloc if o.netloc is not None and len(o.netloc) > 0 else cls.DEFAULT_HOST
        matchObj = re.match( r'^(.+?):([0-9]+)$', hostport, re.M | re.I)
        host = ''
        port = cls.DEFAULT_PORT

        if matchObj:
            host = matchObj.group(1)
            port = int(matchObj.group(2))

        return cls(o.scheme if o.scheme is not None else cls.DEFAULT_SCHEME,
                   host, port)

    def get_url(self):
        return '%s://%s:%s' % (
            self.scheme if self.scheme is not None else self.DEFAULT_SCHEME,
            self.host if self.host is not None else self.DEFAULT_HOST,
            self.port if self.port is not None else self.DEFAULT_PORT
        )


class Retry(object):
    pass


class SimpleRetry(Retry):
    def __init__(self, maxRetry=3, jitterBase=200, jitterRand=50, *args, **kwargs):
        self.maxRetry = maxRetry
        self.jitterBase = jitterBase
        self.jitterRand = jitterRand

    def gen_jitter(self):
        return self.jitterBase + (get_random_integer(2*self.jitterRand) - self.jitterRand)

    def sleep_jitter(self):
        time.sleep(self.gen_jitter()/1000.0)


class BackoffRetry(Retry):
    pass


class Configuration(object):
    def __init__(self, *args, **kwargs):
        # Main endpoints
        self.endpoint_process = Endpoint.url('https://site2.enigabridge.com:11180')
        self.endpoint_enroll = Endpoint.url('https://site2.enigabridge.com:11182')

        # Request configuration - retry + parameters
        self.api_key = 'API_TEST'
        self.http_method = EBConsts.HTTP_METHOD_POST
        self.method = EBConsts.METHOD_REST
        self.timeout = 90000
        self.retry = None
        self.create_tpl = {} # CreateUO template


class UO(object):
    def __init__(self, uo_id=-1, uo_type=-1, enc_key=None, mac_key=None, api_key=None, endpoint=None, configuration=None, *args, **kwargs):
        self.uo_id = uo_id
        self.uo_type = uo_type
        self.enc_key = enc_key
        self.mac_key = mac_key

        self.api_key = api_key
        self.endpoint = endpoint
        self.configuration = configuration

    def resolve_api_key(self):
        if self.api_key is not None:
            return self.api_key
        elif self.configuration is not None:
            return self.configuration.api_key
        else:
            return None

    def resolve_endpoint(self):
        if self.endpoint is not None:
            return self.endpoint
        elif self.configuration is not None:
            return self.configuration.endpoint_process
        else:
            return None

