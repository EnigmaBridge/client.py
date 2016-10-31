import logging
import re
import time
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
    def __init__(self, max_retry=3, jitter_base=200, jitter_rand=50, *args, **kwargs):
        self.max_retry = max_retry
        self.jitter_base = jitter_base
        self.jitter_rand = jitter_rand

    def gen_jitter(self):
        return self.jitter_base + (get_random_range(0, 2*self.jitter_rand) - self.jitter_rand)

    def sleep_jitter(self):
        sleep_time = self.gen_jitter()/1000.0
        time.sleep(sleep_time)


class BackoffRetry(Retry):
    pass


class Configuration(object):
    def __init__(self, *args, **kwargs):
        # Main endpoints
        self.endpoint_process = Endpoint.url('https://site2.enigmabridge.com:11180')
        self.endpoint_enroll = Endpoint.url('https://site2.enigmabridge.com:11182')
        self.endpoint_register = Endpoint.url('https://hut6.enigmabridge.com:8445')

        # Request configuration - retry + parameters
        self.api_key = 'API_TEST'
        self.http_method = EBConsts.HTTP_METHOD_POST
        self.method = EBConsts.METHOD_REST
        self.timeout = 90000
        self.retry = SimpleRetry()
        self.create_tpl = dict()  # CreateUO template

