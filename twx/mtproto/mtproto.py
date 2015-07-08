import os
from socket import socket
import struct
from time import time
from collections import OrderedDict

from random import SystemRandom
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Util.strxor import strxor
from Crypto.Util.number import long_to_bytes, bytes_to_long

from io import BytesIO

from . util import to_hex, crc32, print_hex

from . import rpc
from . import crypt
from . import prime

from . import tl

import sys
import logging
log = logging.getLogger(__name__)


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
        self.auth_key = None
        self.auth_key_id = None
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

        self.send_encrypted_message(getNearestDc)
        # nearestDc = tl.NearestDc(self.recv_message(True))
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
        res_pq = tl.ResPQ.from_stream(self.recv_message())

        assert nonce.value == res_pq.nonce.value

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

        assert p_q_inner_data.nonce.value == self.resPQ.nonce.value

        return p_q_inner_data

    def _req_DH_params(self):

        key = RSA.importKey(self.rsa_key.strip())

        public_key_fingerprint = self.resPQ.server_public_key_fingerprints.items[0]

        data = self.p_q_inner_data.to_boxed_bytes()
        sha_digest = SHA.new(data).digest()
        # get padding of random data to fill what is left after data and sha_digest
        random_bytes = os.urandom(255 - len(data) - len(sha_digest))
        to_encrypt = sha_digest + data + random_bytes  # encrypt cat of sha_digest, data, and padding
        encrypted_data = tl.string_c.from_bytes(key.encrypt(to_encrypt, 0)[0])  # rsa encrypt (key == RSA.key)

        # Presenting proof of work; Server authentication
        req_DH_params = tl.req_DH_params(nonce=self.p_q_inner_data.nonce,
                                         server_nonce=self.p_q_inner_data.server_nonce,
                                         p=self.p_q_inner_data.p, q=self.p_q_inner_data.q,
                                         public_key_fingerprint=public_key_fingerprint,
                                         encrypted_data=encrypted_data)

        self.send_plaintext_message(req_DH_params.to_bytes())
        server_DH_params = tl.Server_DH_Params.from_stream(self.recv_message())

        assert server_DH_params.number == tl.server_DH_params_ok_c.number, "failed to get params"
        assert self.resPQ.nonce.value == server_DH_params.nonce.value
        assert self.resPQ.server_nonce == server_DH_params.server_nonce

        return server_DH_params

    def _create_tmp_aes_keys(self):
        tmp_aes_key = SHA.new(self.p_q_inner_data.new_nonce.to_bytes() + self.server_DH_params.server_nonce.to_bytes()).digest()
        tmp_aes_key += SHA.new(self.server_DH_params.server_nonce.to_bytes() + self.p_q_inner_data.new_nonce.to_bytes()).digest()[:12]

        tmp_aes_iv = SHA.new(self.server_DH_params.server_nonce.to_bytes() + self.p_q_inner_data.new_nonce.to_bytes()).digest()[12:20]
        tmp_aes_iv += SHA.new(self.p_q_inner_data.new_nonce.to_bytes() + self.p_q_inner_data.new_nonce.to_bytes()).digest()
        tmp_aes_iv += self.p_q_inner_data.new_nonce.to_bytes()[0:4]

        return tmp_aes_key, tmp_aes_iv

    def _decrypt_Server_DH_inner_data(self):
        answer_with_hash = crypt.ige_decrypt(self.server_DH_params.encrypted_answer.value, self.tmp_aes_key, self.tmp_aes_iv)

        answer = answer_with_hash[20:]  # decrypted at this point

        server_DH_inner_data = tl.Server_DH_inner_data.from_stream(BytesIO(answer))

        assert self.server_DH_params.nonce.value == server_DH_inner_data.nonce.value
        assert self.server_DH_params.server_nonce.value == server_DH_inner_data.server_nonce.value

        return server_DH_inner_data

    def _create_client_DH_inner_data(self):
        dh_prime = self.server_DH_inner_data.dh_prime.to_int(byteorder='big')
        g = self.server_DH_inner_data.g.value
        g_a = self.server_DH_inner_data.g_a.to_int(byteorder='big')
        server_time = self.server_DH_inner_data.server_time.value
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

        data_with_sha = SHA.new(data).digest() + data
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
                encrypted_data=tl.bytes_c.from_bytes(encrypted_data)
                )

            self.send_plaintext_message(set_client_DH_params.to_bytes())
            self.set_client_DH_params_answer = tl.Set_client_DH_params_answer.from_stream(self.recv_message())

            set_client_DH_params_answer = self.set_client_DH_params_answer

            # print set_client_DH_params_answer
            auth_key = pow(g_a, b, dh_prime)
            auth_key_str = long_to_bytes(auth_key)
            auth_key_sha = SHA.new(auth_key_str).digest()
            auth_key_aux_hash = auth_key_sha[:8]

            new_nonce_hash1 = SHA.new(new_nonce+b'\x01'+auth_key_aux_hash).digest()[-16:]
            new_nonce_hash2 = SHA.new(new_nonce+b'\x02'+auth_key_aux_hash).digest()[-16:]
            new_nonce_hash3 = SHA.new(new_nonce+b'\x03'+auth_key_aux_hash).digest()[-16:]

            assert set_client_DH_params_answer.nonce == self.resPQ.nonce
            assert set_client_DH_params_answer.server_nonce == self.resPQ.server_nonce

            if set_client_DH_params_answer.number == tl.dh_gen_ok_c.number:
                print(set_client_DH_params_answer.new_nonce_hash1, new_nonce_hash1)
                assert set_client_DH_params_answer.new_nonce_hash1.to_bytes() == new_nonce_hash1
                print("Diffie Hellman key exchange processed successfully")

                self.server_salt = strxor(new_nonce[0:8], self.resPQ.server_nonce.to_bytes()[0:8])
                self.auth_key = auth_key_str
                self.auth_key_id = auth_key_sha[-8:]
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
        """
        Unencrypted Message:
            auth_key_id = 0:int64   message_id:int64   message_data_length:int32   message_data:bytes
        """
        # stage 1
        # first one (e.g. req_PQ) message_data == constructor + 16 bytes
        message_id = self.generate_message_id()
        message = (bytes(8) +  # 8 nulls means unencrypted
                   struct.pack('<Q', message_id) +  # message_id = generated unique sequencial ID
                   struct.pack('<I', len(message_data)) +  # len of the API call (including message_data exclusively)
                   message_data)  # actual RPC call
        # stage 2
        #                                 V------ message generated above
        #                                          V------- + 12 to include len, msg_number, and checksum (i.e. total paket length)
        #                                                   V--- gotta increment this shit every fucking packet
        #                                                               V---- append existing byte string
        message = struct.pack('<II', len(message)+12, self.number) + message
        #                   V---- calc chksum of stage 2
        msg_chksum = crc32(message)
        # stage 3: append chksum to end
        message += struct.pack('<I', msg_chksum)
        # ^-- raw data sent over socket

        # yay!
        self.socket.write(message)
        self.number += 1

    def _create_message_aes_key(self, msg_key):
        """
        Defining AES Key and Initialization Vector

        The 2048-bit authorization key (auth_key) and the 128-bit message key (msg_key) are used to compute a
        56-bit AES key (aes_key) and a 256-bit initialization vector (aes_iv) which are subsequently used to
        encrypt the part of the message to be encrypted (i. e. everything with the exception of the external
            header which is added later) with AES-256 in infinite garble extension (IGE) mode.

        The algorithm for computing aes_key and aes_iv from auth_key and msg_key is as follows:

            sha1_a = SHA1 (msg_key + substr (auth_key, x, 32));
            sha1_b = SHA1 (substr (auth_key, 32+x, 16) + msg_key + substr (auth_key, 48+x, 16));
            sha1_с = SHA1 (substr (auth_key, 64+x, 32) + msg_key);
            sha1_d = SHA1 (msg_key + substr (auth_key, 96+x, 32));
            aes_key = substr (sha1_a, 0, 8) + substr (sha1_b, 8, 12) + substr (sha1_c, 4, 12);
            aes_iv = substr (sha1_a, 8, 12) + substr (sha1_b, 0, 8) + substr (sha1_c, 16, 4) + substr (sha1_d, 0, 8);

        where x = 0 for messages from client to server and x = 8 for those from server to client.

        The lower-order 1024 bits of auth_key are not involved in the computation. They may (together with the
        remaining bits or separately) be used on the client device to encrypt the local copy of the data
        received from the server. The 512 lower-order bits of auth_key are not stored on the server;
        therefore, if the client device uses them to encrypt local data and the user loses the key or the
        password, data decryption of local data is impossible (even if data from the server could be obtained).

        When AES is used to encrypt a block of data of a length not divisible by 16 bytes, the data is padded
        with random bytes to the smallest length divisible by 16 bytes immediately prior to being encrypted.
        """
        sha1_a = ...
        sha1_b = ...
        sha1_c = ...
        sha1_d = ...
        aes_key = ...
        aes_iv = ...

    def send_encrypted_message(self, tl_function):  # package message, not chat message
        """
        Ecrypted Message:
            auth_key_id:int64 | msg_key:int128 | encrypted_data:bytes

        Encrypted Message: encrypted_data
            salt:int64 | session_id:int64 | message_id:int64 | seq_no:int32 | message_data_length:int32 | message_data:bytes | padding 0..15:bytes
        """

        if self.auth_key_id is None:
            raise ValueError('auth_key_id is not set')

        if self.session_id is None:
            self.session_id = self.random.getrandbits(64)

        message_data = tl_function.to_bytes()
        message_data_length = len(message_data).to_bytes(4, 'little')
        seq_no = self.number.to_bytes(4, 'little')
        message_id = self.generate_message_id().to_bytes(8, 'little')
        session_id = self.session_id.to_bytes(8, 'little')
        salt = self.server_salt

        plaintext_message_parts = OrderedDict()
        plaintext_message_parts['salt'] = salt
        plaintext_message_parts['session_id'] = session_id
        plaintext_message_parts['message_id'] = message_id
        plaintext_message_parts['seq_no'] = seq_no
        plaintext_message_parts['message_data_length'] = message_data_length
        plaintext_message_parts['message_data'] = message_data

        print('plaintext_message_parts:')
        for key, item in plaintext_message_parts.items():
            print('    {:<20s}:'.format(key), to_hex(item))

        plaintext_message_data = b''.join(plaintext_message_parts.values())

        print('plaintext_message_data  :', to_hex(plaintext_message_data))

        msg_key = sha_digest = SHA.new(plaintext_message_data).digest()[-16:]

        plaintext_message_padding = os.urandom((16 - len(plaintext_message_data) % 16) % 16)
        plaintext_message_data = b''.join([plaintext_message_data, plaintext_message_padding])
        assert len(plaintext_message_data) % 16 == 0

        encrypted_data = crypt.ige_encrypt(plaintext_message_data, self.tmp_aes_key, self.tmp_aes_iv)

        encrypted_message_parts = OrderedDict()
        encrypted_message_parts['auth_key_id'] = self.auth_key_id
        encrypted_message_parts['msg_key'] = msg_key
        encrypted_message_parts['encrypted_data'] = encrypted_data

        print('encrypted_message_parts:')
        for key, item in encrypted_message_parts.items():
            print('    {:<20s}:'.format(key), to_hex(item))

        encrypted_message = b''.join(encrypted_message_parts.values())

        msg_chksum = crc32(encrypted_message).to_bytes(4, 'little')

        message = b''.join([encrypted_message, msg_chksum])

        print('encrypted_message       :', to_hex(encrypted_message))

        self.socket.write(message)
        data = self.socket.read(1024)

        print('recieved_data:', to_hex(data))

        raise NotImplementedError()

        # yay!
        #self.socket.write(message)
        self.number += 1

    def recv_message(self, debug=False):
        """
        Reading socket and receiving message from server. Check the CRC32.
        """
        if debug:
            packet = self.socket.read(1024)  # reads how many bytes to read
            print('debug packet:', to_hex(packet))

        packet_length_data = self.socket.read(4)  # total length of the message
        assert len(packet_length_data) == 4

        packet_length = int.from_bytes(packet_length_data, 'little')

        packet = self.socket.read(packet_length - 4)
        print('packet:', to_hex(packet_length_data), packet_length, len(packet), to_hex(packet))

        # packet = self.socket.read(packet_length)
        # packet_io = BytesIO(packet)

        # check the CRC32
        if crc32(packet_length_data + packet[0:-4]) != struct.unpack('<I', packet[-4:])[0]:
            raise Exception("CRC32 was not correct!")

        auth_key_id = packet[4:12]
        # print('auth_key_id:', auth_key_id)
        if auth_key_id == b'\x00\x00\x00\x00\x00\x00\x00\x00':
            # No encryption - Plain text
            (message_id, message_length) = struct.unpack("<QI", packet[12:24])
            return BytesIO(packet[24:24+message_length])
        elif auth_key_id == self.auth_key_id:
            message_key = packet[12:28]
            encrypted_data = packet[28:-4]
            aes_key, aes_iv = self.aes_calculate(message_key, direction="from server")
            decrypted_data = crypt.ige_decrypt(encrypted_data, aes_key, aes_iv)
            assert decrypted_data[0:8] == self.server_salt
            assert decrypted_data[8:16] == self.session_id
            # message_id = decrypted_data[16:24]
            # seq_no = struct.unpack("<I", decrypted_data[24:28])[0]
            message_data_length = struct.unpack("<I", decrypted_data[28:32])[0]
            return BytesIO(decrypted_data[32:32+message_data_length])

        raise Exception("Got unknown auth_key id")

    def __del__(self):
        # cleanup
        self._socket.close()


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
