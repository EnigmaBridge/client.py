#!/usr/bin/env python
# -*- coding: utf-8 -*-

from ebclient.process_data import ProcessData
# from ebclient.create_uo import KeyTypes, Environment, Gen
from ebclient.create_uo import TemplateFields
from ebclient.eb_create_uo import *
from ebclient.uo import Configuration, Endpoint, SimpleRetry
# from ebclient.uo import UO
# from ebclient.crypto_util import *
import unittest
# import mock
# import sys
# import six

__author__ = 'Enigma Bridge Ltd'


class CreateUOTest(unittest.TestCase):
    """Tests for ebclient.ProcessData"""

    def setUp(self):
        self.cfg = Configuration()
        self.cfg.endpoint_process = Endpoint.url('https://site2.enigmabridge.com:11180')
        self.cfg.endpoint_enroll = Endpoint.url('https://site2.enigmabridge.com:11182')
        self.cfg.api_key = 'API_TEST'
        self.cfg.retry = SimpleRetry(max_retry=5, jitter_base=1000, jitter_rand=250)
        pass

    def tearDown(self):
        pass

    def test_create_uo_rsa(self):
        cou = CreateUO(configuration=self.cfg,
                       tpl={
                           TemplateFields.environment: Environment.DEV
                       })

        rsa_key = cou.create_rsa(1024)

        # Process data - try to decrypt one.
        pd = ProcessData(uo=rsa_key.uo, config=self.cfg)

        data_in = ("\x00"*127) + "\x01"
        result = pd.call(data_in)
        self.assertEqual(data_in, result, "Result does not match")


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
