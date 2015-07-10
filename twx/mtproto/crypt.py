# -*- coding: utf-8 -*-
# Author: Sammy Pfeiffer
# Author: Anton Grigoryev
# This file implements the AES 256 IGE cipher
# working in Python 2.7 and Python 3.4 (other versions untested)
# as it's needed for the implementation of Telegram API
# It's based on PyCryto

from __future__ import print_function
from Crypto.Util.strxor import strxor
from Crypto.Cipher import AES
from Crypto.Hash import SHA

import logging
log = logging.getLogger(__name__)

# AES 256 IGE part


def SHA1(data):
    return SHA.new(data).digest()

def ige_encrypt(message, key, iv):
    return _ige(message, key, iv, operation="encrypt")


def ige_decrypt(message, key, iv):
    return _ige(message, key, iv, operation="decrypt")


def _ige(message, key, iv, operation="decrypt"):
    """Given a key, given an iv, and message
     do whatever operation asked in the operation field.
     Operation will be checked for: "decrypt" and "encrypt" strings.
     Returns the message encrypted/decrypted.
     message must be a multiple by 16 bytes (for division in 16 byte blocks)
     key must be 32 byte
     iv must be 32 byte (it's not internally used in AES 256 ECB, but it's
     needed for IGE)"""
    message = bytes(message)
    if len(key) != 32:
        raise ValueError("key must be 32 bytes long (was " +
                         str(len(key)) + " bytes)")
    if len(iv) != 32:
        raise ValueError("iv must be 32 bytes long (was " +
                         str(len(iv)) + " bytes)")

    cipher = AES.new(key, AES.MODE_ECB, iv)
    blocksize = cipher.block_size

    if len(message) % blocksize != 0:
        raise ValueError("message must be a multiple of 16 bytes (try adding " +
                         str(16 - len(message) % 16) + " bytes of padding)")

    ivp = iv[0:blocksize]
    ivp2 = iv[blocksize:]

    ciphered = bytes()

    for i in range(0, len(message), blocksize):
        indata = message[i:i+blocksize]
        if operation == "decrypt":
            xored = strxor(indata, ivp2)
            decrypt_xored = cipher.decrypt(xored)
            outdata = strxor(decrypt_xored, ivp)
            ivp = indata
            ivp2 = outdata
        elif operation == "encrypt":
            xored = strxor(indata, ivp)
            encrypt_xored = cipher.encrypt(xored)
            outdata = strxor(encrypt_xored, ivp2)
            ivp = outdata
            ivp2 = indata
        else:
            raise ValueError("operation must be either 'decrypt' or 'encrypt'")
        ciphered += outdata
    return ciphered

class AESKey(bytes):

    def __new__(cls, value):
        value = bytes(value)

        bit_length = len(value) * 8

        if bit_length == AES256Key.bit_length:
            cls = AES256Key
        else:
            raise ValueError('Unsupported AES key bit length: {}'.format(bit_length))

        return cls._from_bytes(value)

class AES256Key(AESKey):

    bit_length = 256

    def __new__(cls, value):
        return super(AES256Key, cls).__new__(cls, value)

    @classmethod
    def _from_bytes(cls, value):
        result = bytes.__new__(cls, value)
        if len(result) != 32:
            raise ValueError('value must be 256 bits (32 bytes)'.format(bit_length))
        return result


class RSAKey(bytes):

    def __new__(cls, value):
        value = bytes(value)

        bit_length = len(value) * 8

        if bit_length == RSA2048Key.bit_length:
            cls = RSA2048Key
        else:
            raise ValueError('Unsupported RSAKey key bit length: {}'.format(bit_length))

        return cls._from_bytes(value)

class RSA2048Key(RSAKey):

    bit_length = 2048

    def __new__(cls, value):
        return super(RSA2048Key, cls).__new__(cls, value)

    @classmethod
    def _from_bytes(cls, value):
        result = bytes.__new__(cls, value)
        if len(result) != 256:
            raise ValueError('value must be 2048 bits (256 bytes)'.format(bit_length))
        return result
