import logging
import re
from eb_utils import EBUtils
from eb_consts import EBConsts
from py3compat import *

__author__ = 'dusanklinec'


logger = logging.getLogger(__name__)


class Endpoint(object):
    def __init__(self, scheme='https', host='site2.enigmabridge.com', port=11180, *args, **kwargs):
        self.scheme = scheme
        self.host = host
        self.port = port

    @classmethod
    def url(cls, url):
        o = parse_url(url)
        hostport = o.netloc if o.netloc is not None and len(o.netloc) > 0 else 'site2.enigmabridge.com:11180'
        matchObj = re.match( r'^(.+?):([0-9]+)$', hostport, re.M | re.I)
        host = ''
        port = 11180

        if matchObj:
            host = matchObj.group(1)
            port = int(matchObj.group(2))

        return cls(o.scheme if o.scheme is not None else 'https',
                   host, port)


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

