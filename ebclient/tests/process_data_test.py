#!/usr/bin/env python
# -*- coding: utf-8 -*-

from ebclient.process_data import ProcessData
from ebclient.uo import Configuration, Endpoint, SimpleRetry, UO
from ebclient.crypto_util import *
import unittest
# import mock
# import sys
# import six


__author__ = 'dusanklinec'


class ProcessDataTest(unittest.TestCase):
    """Tests for ebclient.ProcessData"""

    def setUp(self):
        self.cfg = Configuration()
        self.cfg.endpoint_process = Endpoint.url('https://site2.enigmabridge.com:11180')
        self.cfg.api_key = 'API_TEST'
        self.cfg.retry = SimpleRetry()

        self.uo_aes = UO(uo_id=0xee01,
                         uo_type=0x4,
                         enc_key=from_hex('e134567890123456789012345678901234567890123456789012345678901234'),
                         mac_key=from_hex('e224262820223456789012345678901234567890123456789012345678901234'),
                         configuration=self.cfg)
        pass

    def tearDown(self):
        pass

    def test_process_data(self):
        pd = ProcessData(uo=self.uo_aes, config=self.cfg)
        result = pd.call(from_hex('6bc1bee22e409f96e93d7e117393172a'))
        self.assertEqual(from_hex('95c6bb9b6a1c3835f98cc56087a03e82'), result, "Result does not match")

if __name__ == "__main__":
    unittest.main()  # pragma: no cover

