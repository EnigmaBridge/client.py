import logging

__author__ = 'dusanklinec'


logger = logging.getLogger(__name__)


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
            return self.configuration.endpoint
        else:
            return None

