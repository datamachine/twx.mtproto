import os
from socket import socket
import struct
from time import time
from collections import OrderedDict

from random import SystemRandom
from Crypto.PublicKey import RSA
from Crypto.Util.strxor import strxor
from Crypto.Util.number import long_to_bytes, bytes_to_long

from io import BytesIO

from . util import to_hex, crc32, print_hex, substr
from . crypt import SHA1

from . import rpc
from . import crypt
from . import prime

from . import tl

from . authkey import MTProtoAuthKey, aes_encrypt, aes_decrypt

import sys
import logging
log = logging.getLogger(__name__)

from collections import namedtuple
from struct import Struct

class MTProto:

    def __init__(self, api_secret, api_id, rsa_key):
        self.api_secret = api_secret
        self.api_id = api_id
        self.dc = Datacenter(0, Datacenter.DCs_test[1], 443, rsa_key)


class Datacenter:
    DATA_VERSION = 4

    DCs = [
        "149.154.175.50",
        "149.154.167.51",
        "149.154.175.100",
        "149.154.167.91",
        "149.154.171.5",
    ]

    DCs_ipv6 = [
        "2001:b28:f23d:f001::a",
        "2001:67c:4e8:f002::a",
        "2001:b28:f23d:f003::a",
        "2001:67c:4e8:f004::a",
        "2001:b28:f23f:f005::a",
    ]

    DCs_test = [
        "149.154.175.10",
        "149.154.167.40",
        "149.154.175.117",
    ]

    DCs_test_ipv6 = [
        "2001:b28:f23d:f001::e",
        "2001:67c:4e8:f002::e",
        "2001:b28:f23d:f003::e",
    ]

    def __init__(self, dc_id, ipaddr, port, rsa_key):
        self.random = SystemRandom()

        self.session_id = None

        self.resPQ = None
        self.p_q_inner_data = None
        self.server_DH_params = None
        self.server_DH_inner_data = None
        self.client_DH_inner_data = None
        tmp_aes_key = None
        tmp_aes_iv = None
        self.set_client_DH_params_answer = None

        self.ipaddr = ipaddr
        self.port = port
        self.datacenter_id = dc_id
        self.auth_server_salt_set = []
        self._socket = socket()
        self._socket.connect((ipaddr, port))
        self._socket.settimeout(5.0)
        self.socket = self._socket.makefile(mode='rwb', buffering=0)
        self.message_queue = []

        self.last_msg_id = 0
        self.timedelta = 0
        self.number = 0

        self.authorized = False
        self.auth_key = MTProtoAuthKey()
        self.server_salt = None
        self.server_time = None

        self.MAX_RETRY = 5
        self.AUTH_MAX_RETRY = 5

        self.rsa_key = rsa_key

        self.b = self.random.getrandbits(2048)

        # Handshake
        self.create_auth_key()
        self.test_api()
        # print(self.auth_key)
        # print(self.server_salt)

    def test_api(self):
        getNearestDc = tl.help_getNearestDc()
        print(getNearestDc)

        self.send_encrypted_message(getNearestDc.to_bytes())
        self.recv_encrypted_message()
        # nearestDc = tl.NearestDc(self.recv_plaintext_message(True))
        # print(nearestDc)

    """
    g = public (prime) base, known to Alice, Bob, and Eve. g = 5
    p = public (prime) number, known to Alice, Bob, and Eve. p = 23
    a = Alice's private key, known only to Alice. a = 6
    b = Bob's private key known only to Bob. b = 15
    """

    def _req_pq(self):
        nonce = tl.int128_c(self.random.getrandbits(128))
        request = tl.req_pq(nonce)
        self.send_plaintext_message(request.to_bytes())
        res_pq = tl.ResPQ.from_stream(BytesIO(self.recv_plaintext_message()))

        assert nonce == res_pq.nonce

        return res_pq

    def _create_p_q_inner_data(self):
        pq = self.resPQ.pq.to_int('big')

        p, q = prime.primefactors(pq)
        if p > q:
            p, q = q, p

        assert p * q == pq and p < q

        p_string = tl.string_c.from_int(p, byteorder='big')
        q_string = tl.string_c.from_int(q, byteorder='big')

        new_nonce = tl.int256_c(self.random.getrandbits(256))

        p_q_inner_data = tl.p_q_inner_data_c(pq=self.resPQ.pq, p=p_string, q=q_string, nonce=self.resPQ.nonce, server_nonce=self.resPQ.server_nonce, new_nonce=new_nonce)

        assert p_q_inner_data.nonce == self.resPQ.nonce

        return p_q_inner_data

    def _req_DH_params(self):

        key = RSA.importKey(self.rsa_key.strip())

        public_key_fingerprint = self.resPQ.server_public_key_fingerprints[0]

        data = self.p_q_inner_data.to_boxed_bytes()
        sha_digest = SHA1(data)
        # get padding of random data to fill what is left after data and sha_digest
        random_bytes = os.urandom(255 - len(data) - len(sha_digest))
        to_encrypt = sha_digest + data + random_bytes  # encrypt cat of sha_digest, data, and padding
        encrypted_data = tl.string_c(key.encrypt(to_encrypt, 0)[0])  # rsa encrypt (key == RSA.key)

        # Presenting proof of work; Server authentication
        req_DH_params = tl.req_DH_params(nonce=self.p_q_inner_data.nonce,
                                         server_nonce=self.p_q_inner_data.server_nonce,
                                         p=self.p_q_inner_data.p, q=self.p_q_inner_data.q,
                                         public_key_fingerprint=public_key_fingerprint,
                                         encrypted_data=encrypted_data)

        self.send_plaintext_message(req_DH_params.to_bytes())
        server_DH_params = tl.Server_DH_Params.from_stream(BytesIO(self.recv_plaintext_message()))

        assert server_DH_params.number == tl.server_DH_params_ok_c.number, "failed to get params"
        assert self.resPQ.nonce == server_DH_params.nonce
        assert self.resPQ.server_nonce == server_DH_params.server_nonce

        return server_DH_params

    def _create_tmp_aes_keys(self):
        tmp_aes_key = SHA1(self.p_q_inner_data.new_nonce.to_bytes() + self.server_DH_params.server_nonce.to_bytes())
        tmp_aes_key += SHA1(self.server_DH_params.server_nonce.to_bytes() + self.p_q_inner_data.new_nonce.to_bytes())[:12]

        tmp_aes_iv = SHA1(self.server_DH_params.server_nonce.to_bytes() + self.p_q_inner_data.new_nonce.to_bytes())[12:20]
        tmp_aes_iv += SHA1(self.p_q_inner_data.new_nonce.to_bytes() + self.p_q_inner_data.new_nonce.to_bytes())
        tmp_aes_iv += self.p_q_inner_data.new_nonce.to_bytes()[0:4]

        return tmp_aes_key, tmp_aes_iv

    def _decrypt_Server_DH_inner_data(self):
        answer_with_hash = crypt.ige_decrypt(self.server_DH_params.encrypted_answer, self.tmp_aes_key, self.tmp_aes_iv)

        answer = answer_with_hash[20:]  # decrypted at this point

        server_DH_inner_data = tl.Server_DH_inner_data.from_stream(BytesIO(answer))

        assert self.server_DH_params.nonce == server_DH_inner_data.nonce
        assert self.server_DH_params.server_nonce == server_DH_inner_data.server_nonce

        return server_DH_inner_data

    def _create_client_DH_inner_data(self):
        dh_prime = self.server_DH_inner_data.dh_prime.to_int(byteorder='big')
        g = self.server_DH_inner_data.g
        g_a = self.server_DH_inner_data.g_a.to_int(byteorder='big')
        server_time = self.server_DH_inner_data.server_time
        self.timedelta = server_time - time()  # keep in mind delta is used somewhere later

        assert prime.isprime(dh_prime)
        retry_id = tl.long_c(0)
        b = self.b
        g_b = pow(g, b, dh_prime)

        g_b_str = tl.bytes_c.from_int(g_b, byteorder='big')

        client_DH_inner_data = tl.client_DH_inner_data_c(
            nonce=self.server_DH_inner_data.nonce,
            server_nonce=self.server_DH_inner_data.server_nonce,
            retry_id=retry_id,
            g_b=g_b_str)

        return client_DH_inner_data

    def create_auth_key(self):
        self.resPQ = self._req_pq()
        print(self.resPQ)

        self.p_q_inner_data = self._create_p_q_inner_data()
        print(self.p_q_inner_data)

        self.server_DH_params = self._req_DH_params()
        print(self.server_DH_params)

        self.tmp_aes_key, self.tmp_aes_iv = self._create_tmp_aes_keys()

        self.server_DH_inner_data = self._decrypt_Server_DH_inner_data()
        print(self.server_DH_inner_data)

        self.client_DH_inner_data = self._create_client_DH_inner_data()
        print(self.client_DH_inner_data)

        data = self.client_DH_inner_data.to_boxed_bytes()

        data_with_sha = SHA1(data) + data
        data_with_sha_padded = data_with_sha + os.urandom(-len(data_with_sha) % 16)
        encrypted_data = crypt.ige_encrypt(data_with_sha_padded, self.tmp_aes_key, self.tmp_aes_iv)

        g_a = self.server_DH_inner_data.g_a.to_int(byteorder='big')
        dh_prime = self.server_DH_inner_data.dh_prime.to_int(byteorder='big')
        b = self.b
        new_nonce = self.p_q_inner_data.new_nonce.to_bytes()

        for i in range(1, self.AUTH_MAX_RETRY):  # retry when dh_gen_retry or dh_gen_fail
            set_client_DH_params = tl.set_client_DH_params(
                nonce=self.resPQ.nonce,
                server_nonce=self.resPQ.server_nonce,
                encrypted_data=tl.bytes_c(encrypted_data)
                )

            self.send_plaintext_message(set_client_DH_params.to_bytes())
            self.set_client_DH_params_answer = tl.Set_client_DH_params_answer.from_stream(BytesIO(self.recv_plaintext_message()))

            set_client_DH_params_answer = self.set_client_DH_params_answer

            # print set_client_DH_params_answer
            auth_key = pow(g_a, b, dh_prime)
            auth_key_str = long_to_bytes(auth_key)
            auth_key_sha = SHA1(auth_key_str)
            auth_key_aux_hash = auth_key_sha[:8]

            new_nonce_hash1 = SHA1(new_nonce+b'\x01'+auth_key_aux_hash)[-16:]
            new_nonce_hash2 = SHA1(new_nonce+b'\x02'+auth_key_aux_hash)[-16:]
            new_nonce_hash3 = SHA1(new_nonce+b'\x03'+auth_key_aux_hash)[-16:]

            assert set_client_DH_params_answer.nonce == self.resPQ.nonce
            assert set_client_DH_params_answer.server_nonce == self.resPQ.server_nonce

            if set_client_DH_params_answer.number == tl.dh_gen_ok_c.number:
                print(set_client_DH_params_answer.new_nonce_hash1, new_nonce_hash1)
                assert set_client_DH_params_answer.new_nonce_hash1.to_bytes() == new_nonce_hash1
                print("Diffie Hellman key exchange processed successfully")

                self.server_salt = strxor(new_nonce[0:8], self.resPQ.server_nonce.to_bytes()[0:8])
                self.auth_key.set_key(auth_key_str)
                print("Auth key generated")
                return "Auth Ok"
            elif set_client_DH_params_answer.number == tl.dh_gen_retry_c.number:
                assert set_client_DH_params_answer.new_nonce_hash2.to_bytes() == new_nonce_hash2
                print("Retry Auth")
            elif set_client_DH_params_answer.status == tl.dh_gen_fail_c.number:
                assert set_client_DH_params_answer.new_nonce_hash3.to_bytes() == new_nonce_hash3
                print("Auth Failed")
                raise Exception("Auth Failed")
            else:
                raise Exception("Response Error")

    def generate_message_id(self):
        msg_id = int(time() * 2**32)
        if self.last_msg_id > msg_id:
            msg_id = self.last_msg_id + 1
        while msg_id % 4 is not 0:
            msg_id += 1

        return msg_id

    def send_plaintext_message(self, message_data):  # package message, not chat message
        msg = MTProtoUnencryptedMessage.new(self.generate_message_id(), message_data)
        self.send_tcp_message(msg)

    def recv_plaintext_message(self):
        tcp_msg = self.recv_tcp_message()
        msg = MTProtoUnencryptedMessage.from_bytes(tcp_msg.payload)

        if msg.is_encrypted():
            raise ValueError('did not get a plaintext message')

        return msg.message_data

    def send_encrypted_message(self, message_data):
        """
        Ecrypted Message:
            auth_key_id:int64 | msg_key:int128 | encrypted_data:bytes

        Encrypted Message: encrypted_data
            salt:int64 | session_id:int64 | message_id:int64 | seq_no:int32 | message_data_length:int32 | message_data:bytes | padding 0..15:bytes
        """

        if self.session_id is None:
            self.session_id = self.random.getrandbits(64).to_bytes(8, 'little')

        msg = MTProtoEncryptedMessage.new(
                    int.from_bytes(self.server_salt, 'little'),
                    int.from_bytes(self.session_id, 'little'),
                    self.generate_message_id(),
                    1,
                    message_data)
        msg = msg.encrypt(self.auth_key)

        self.send_tcp_message(msg)

    def recv_encrypted_message(self):
        tcp_msg = self.recv_tcp_message()

        msg = MTProtoEncryptedMessage.from_bytes(tcp_msg.payload)
        msg = msg.decrypt(self.auth_key)

        print('message_data:', to_hex(msg.encrypted_data.message_data))

        """
        at this point, message_data looks a lot like this:
        message_data: 
            Msg container -> DCF8F173
                Vector<%Message>
                num_items:int -> 02000000 
                    %Message:
                        message_id:long -> 01D40F39 3BBFA055 
                        seq_no:int -> 01000000 
                        bytes:int -> 1C000000
                        body:Object -> 
                            new_session_created -> 0809C29E 
                                first_msg_id:long -> 00C8A02B 3BBFA055
                                unique_id:long -> 1A1D5711 00A96EC3
                                server_salt:long -> 74EEA560 D1AB64E3
                    %Message:
                        message_id -> 01541139 3BBFA055
                        seq_no:int -> 02000000
                        bytes:int -> 14000000
                        body:Object -> 
                            msg_acks -> 59B4D662 

                                Vector<long> -> 15C4B51C 
                                    count -> 01000000
                                    long -> 00C8A02B 3BBFA055
        """

    def send_tcp_message(self, mproto_message):
        tcp_msg = MTProtoTCPMessage.new(self.number, mproto_message)
        self.socket.write(tcp_msg.to_bytes())
        self.number += 1

    def recv_tcp_message(self):
        tcp_msg = MTProtoTCPMessage.from_stream(self.socket)

        if not tcp_msg.crc_ok():
            raise ValueError('mproto_message checksum for tcp does not match')

        return tcp_msg

    def __del__(self):
        # cleanup
        self._socket.close()

class MTProtoMessage:

    @classmethod
    def from_tcp_msg(cls, tcp_msg):
        if cls is MTProtoMessage:
            if tcp_msg.payload[0:8] == b'\x00\x00\x00\x00\x00\x00\x00\x00':
                return MTProtoUnencryptedMessage(tcp_msg.payload)
            else:
                return MTProtoEncryptedMessage(tcp_msg.payload)
        else:
            return cls(tcp_msg)

    def is_encrypted(self):
        return self.auth_key_id != 0
    

class MTProtoEncryptedMessage(namedtuple('MTProtoEncryptedMessage',
    'auth_key_id msg_key encrypted_data'), MTProtoMessage):

    """
    Ecrypted Message:
        auth_key_id:int64 | msg_key:int128 | encrypted_data:bytes
    Encrypted Message: encrypted_data
        salt:int64 | session_id:int64 | message_id:int64 | seq_no:int32 | message_data_length:int32 | message_data:bytes | padding 0..15:bytes
    """

    class EncryptedData(namedtuple('EncrypedData', 'salt session_id message_id seq_no message_data_length message_data')):

        _header_struct = Struct('<QQQII')
    
        @classmethod
        def new(cls, salt, session_id, message_id, seq_no, message_data):
            return cls(salt, session_id, message_id, seq_no, len(message_data), message_data)

        def padding_bytes(self):
            return os.urandom((16 - (32 + len(self.message_data)) % 16) % 16)

        def to_bytes(self):
            return self._header_struct.pack(self.salt, self.session_id, self.message_id, self.seq_no, self.message_data_length) + self.message_data

        @classmethod
        def from_bytes(cls, data):
            parts = list(cls._header_struct.unpack(data[0:32]))
            message_data_length = parts[-1]
            parts.append(data[32:32+message_data_length])
            return cls(*parts)

    @classmethod
    def new(cls, salt, session_id, message_id, seq_no, message_data):

        encrypted_data = cls.EncryptedData.new(salt, session_id, message_id, seq_no, message_data)
        return cls(None, None, encrypted_data)

    def encrypt(self, auth_key):
        unencryped_data = self.encrypted_data.to_bytes()
        msg_key = SHA1(unencryped_data)[-16:]
        unencryped_data += self.encrypted_data.padding_bytes()

        assert len(unencryped_data) % 16 == 0

        encrypted_data = aes_encrypt(unencryped_data, auth_key, msg_key)
        return MTProtoEncryptedMessage(auth_key.key_id, msg_key, encrypted_data)

    def decrypt(self, auth_key):
        decrypted_data = aes_decrypt(self.encrypted_data, auth_key, self.msg_key)
        return self._replace(encrypted_data=MTProtoEncryptedMessage.EncryptedData.from_bytes(decrypted_data))

    @classmethod
    def from_bytes(cls, data):
        return cls(data[0:8], data[8:24], data[24:])

    def to_bytes(self):
        return b''.join((self.auth_key_id, self.msg_key, self.encrypted_data,))


class MTProtoUnencryptedMessage(MTProtoMessage,
    namedtuple('MTProtoUnencryptedMessage', 'auth_key_id message_id message_data_length message_data')):

    """
    Unencrypted Message:
        auth_key_id = 0:int64   message_id:int64   message_data_length:int32   message_data:bytes
    """

    _header_struct = Struct('<QQI')

    @classmethod
    def new(cls, message_id, message_data):
        return cls.__new__(cls, 0, message_id, len(message_data), message_data)

        result = cls.__new__(cls)
        result.data = cls._header_struct.pack(0, message_id, len(message_data)) + message_data
        return result

    @classmethod
    def from_bytes(cls, data):
        auth_key_id, message_id, message_data_length = cls._header_struct.unpack(data[0:20])
        return cls(auth_key_id, message_id, message_data_length, data[20:])

    def to_bytes(self):
        return self._header_struct.pack(self.auth_key_id, self.message_id, self.message_data_length) + self.message_data

class MTProtoTCPMessage(namedtuple('MTProtoTCPMessage', 'data')):

    @classmethod
    def new(cls, seq_no, mtproto_msg):
        payload = mtproto_msg.to_bytes()
        header_and_payload = bytes().join([
            int.to_bytes(len(payload) + 12, 4, 'little'),
            int.to_bytes(seq_no, 4, 'little'),
            payload
            ])
        crc = tl.int_c._to_bytes(crc32(header_and_payload))

        return cls(header_and_payload + crc)

    @classmethod
    def from_stream(cls, stream):
        length_bytes = stream.read(4)
        length = int.from_bytes(length_bytes, 'little')

        return cls(length_bytes + stream.read(length))

    @property
    def length(self):
        return int.from_bytes(self.data[0:4], 'little')

    @property
    def seq_no(self):
        return int.from_bytes(self.data[4:8], 'little')

    @property
    def payload(self):
        return self.data[8:-4]

    @property
    def crc(self):
        return int.from_bytes(self.data[-4:], 'little')

    def crc_ok(self):
        return self.crc == crc32(self.data[:-4])

    def to_bytes(self):
        return self.data


class MTProtoClient:

    def __init__(self, config):
        from urllib.parse import urlsplit

        self.api_id = config.get('app', 'api_id')
        self.api_hash = config.get('app', 'api_hash')
        self.app_title = config.get('app', 'app_title')
        self.short_name = config.get('app', 'short_name')
        self.public_keys = config.get('servers', 'public_keys')
        self.test_dc = urlsplit(config.get('servers', 'test_dc'))

    def init_connection(self):
        MTProto('FFFFFFFFF', 'EEEEEEEE', self.public_keys)
