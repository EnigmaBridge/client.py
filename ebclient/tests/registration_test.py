from ebclient.eb_registration import *
from ebclient.registration import *
from ebclient.uo import Configuration, Endpoint, SimpleRetry, UO
from ebclient.crypto_util import *
import unittest
import json


__author__ = 'dusanklinec'


class RegistrationTest(unittest.TestCase):
    """Tests for ebclient.eb_registration"""

    def setUp(self):
        self.cfg = Configuration()
        self.cfg.endpoint_register = Endpoint.url('https://hut3.enigmabridge.com:8445')
        self.cfg.retry = SimpleRetry()
        pass

    def tearDown(self):
        pass

    def test_registration(self):
        client_data_reg = {
            'name': 'test',
            'authentication': 'type',
            'type': 'test',
            'token': 'LSQJCHT61VTEMFQBZADO'
        }

        regreq = RegistrationRequest(client_data=client_data_reg, env=ENVIRONMENT_DEVELOPMENT, config=self.cfg)
        regresponse = regreq.call()
        print(json.dumps(regresponse, indent=2))

        client_api_req = {
            'authentication': 'password',
            'username': regresponse['username'],
            'password': regresponse['password']
        }

        endpoint = {
            "ipv4": "123.23.23.23",
            "ipv6": "fe80::2e0:4cff:fe68:bcc2/64",
            "country": "gb",
            "network": "plusnet",
            "location": [0.34,10]
        }

        apireq = ApiKeyRequest(client_data=client_api_req, endpoint=endpoint, env=ENVIRONMENT_DEVELOPMENT, config=self.cfg)
        apiresponse = apireq.call()
        print(json.dumps(apiresponse, indent=2))


if __name__ == "__main__":
    unittest.main()  # pragma: no cover

