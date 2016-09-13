__author__ = 'dusanklinec'
"""
Provides basic cryptographic utilities for the Python EnigmaBridge client, e.g.,
generating random numbers, encryption, decryption, padding, etc...

For now we use PyCrypto, later we may use pure python implementations to minimize dependency count.
"""

import logging
import os
import base64
import types

from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util.py3compat import *
from Crypto.Util.number import long_to_bytes, bytes_to_long, size, ceil_div

# Logging if needed
logger = logging.getLogger(__name__)

#
# Utils
#


def to_bytes(x):
    """
    Converts input to a byte string.
    Typically used in PyCrypto as an argument (e.g., key, iv)

    :param x: string (does nothing), bytearray, array with numbers
    :return:
    """
    if isinstance(x, bytearray):
        return x.decode('ascii')
    elif isinstance(x, basestring):
        return x
    elif isinstance(x, (list, tuple)):
        return bytearray(x).decode('ascii')
    elif isinstance(x, types.LongType):
        return long_to_bytes(x)
    else:
        raise ValueError('Unknown input argument type')


def to_long(x):
    """
    Converts input to a long number (arbitrary precision python long)
    :param x:
    :return:
    """
    if isinstance(x, types.LongType):
        return x
    elif isinstance(x, types.IntType):
        return long(x)
    else:
        return bytes_to_long(to_bytes(x))


def to_bytearray(x):
    """
    Converts input to byte array.
    If already a byte array, return directly.

    :param x:
    :return:
    """
    if isinstance(x, bytearray):
        return x
    else:
        return bytearray(x)


def to_hex(x):
    """
    Converts input to the hex string
    :param x:
    :return:
    """
    if isinstance(x, bytearray):
        return x.decode('hex')
    elif isinstance(x, basestring):
        return base64.b16encode(x)
    elif isinstance(x, (list, tuple)):
        return bytearray(x).decode('hex')
    else:
        raise ValueError('Unknown input argument type')


def long_bit_size(x):
    return size(x)


def long_byte_size(x):
    return ceil_div(long_bit_size(x), 8)


def get_zero_vector(numBytes):
    """
    Generates a zero vector of a given size

    :param numBytes:
    :return:
    """
    return bytearray([0] * numBytes).decode('ascii')


#
# Randomness
#


def get_random_vector(numBytes):
    #return Random.get_random_bytes(numBytes)
    return os.urandom(numBytes)


#
# Padding
#


class Padding(object):
    """
    Basic Padding methods
    """
    @staticmethod
    def pad(data, *args, **kwargs):  # pragma: no cover
        """Pads data with given padding.

        :returns: Padded data.
        :rtype: list

        """
        raise NotImplementedError()

    @staticmethod
    def unpad(data, *args, **kwargs):  # pragma: no cover
        """UnPads data with given padding.

        :returns: unpaded data
        :rtype: list

        """
        raise NotImplementedError()


class EmptyPadding(Padding):
    @staticmethod
    def unpad(data, *args, **kwargs):
        return data

    @staticmethod
    def pad(data, *args, **kwargs):
        return data


class PKCS7(Padding):
    @staticmethod
    def unpad(data, *args, **kwargs):
        return data[:-ord(data[len(data)-1:])]

    @staticmethod
    def pad(data, *args, **kwargs):
        bs = kwargs.get('bs', 16)
        return data + (bs - len(data) % bs) * chr(bs - len(data) % bs)


class PKCS15(Padding):
    @staticmethod
    def unpad(data, *args, **kwargs):
        #TODO: implement
        pass

    @staticmethod
    def pad(data, *args, **kwargs):
        #TODO: implement
        pass


#
# Encryption
#

def aes_cbc(key):
    """
    Returns AES-CBC instance that can be used for [incremental] encryption/decryption in ProcessData.
    Uses zero IV.

    :param key:
    :return:
    """
    return AES.new(key, AES.MODE_CBC, get_zero_vector(16))


def aes(encrypt, key, data):
    """
    One-pass AES-256-CBC used in ProcessData. Zero IV (don't panic, IV-like random nonce is included in plaintext in the
    first block in ProcessData).

    Does not use padding (data has to be already padded).

    :param encrypt:
    :param key:
    :param data:
    :return:
    """
    cipher = AES.new(key, AES.MODE_CBC, get_zero_vector(16))
    if encrypt:
        return cipher.encrypt(data)
    else:
        return cipher.decrypt(data)


def aes_enc(key, data):
    return aes(True, key, data)


def aes_dec(key, data):
    return aes(False, key, data)


def mac(key, data):
    """
    AES-265-CBC-MAC on the data used in ProcessData.
    Does not use padding (data has to be already padded).

    :param key:
    :param data:
    :return:
    """
    engine = AES.new(key, AES.MODE_CBC, get_zero_vector(16))
    return engine.encrypt(data)[-16:]


def rsa_enc(data, modulus, exponent):
    """
    Simple RAW RSA encryption method, returns byte string.
    Returns byte string of the same size as the modulus (left padded with 0)

    :param data:
    :param modulus:
    :param exponent:
    :return:
    """
    modulus = to_long(modulus)
    exponent = to_long(exponent)
    data = to_long(data)

    return long_to_bytes(pow(data, exponent, modulus), long_byte_size(modulus))

