import os
from socket import socket
import struct
from time import time

from random import SystemRandom
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Util.strxor import strxor
from Crypto.Util.number import long_to_bytes, bytes_to_long

from io import BytesIO

from . util import to_hex, crc32

from . import rpc
from . import crypt
from . import prime

from . import tl

import sys
import logging
log = logging.getLogger(__name__)


class MTProto:

    def __init__(self, api_secret, api_id):
        self.api_secret = api_secret
        self.api_id = api_id
        self.dc = Datacenter(0, Datacenter.DCs_test[1], 443)


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

    def __init__(self, dc_id, ipaddr, port):
        self.random = SystemRandom()

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

        # TODO: Pass this in
        self.rsa_key = """-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAwVACPi9w23mF3tBkdZz+zwrzKOaaQdr01vAbU4E1pvkfj4sqDsm6
lyDONS789sVoD/xCS9Y0hkkC3gtL1tSfTlgCMOOul9lcixlEKzwKENj1Yz/s7daS
an9tqw3bfUV/nqgbhGX81v/+7RFAEd+RwFnK7a+XYl9sluzHRyVVaTTveB2GazTw
Efzk2DWgkBluml8OREmvfraX3bkHZJTKX4EQSjBbbdJ2ZXIsRrYOXfaA+xayEGB+
8hdlLmAjbCVfaigxX0CDqWeR1yFL9kwd9P0NsZRPsmoqVwMbMu7mStFai6aIhc3n
Slv8kg9qv1m6XHVQY3PnEw+QQtqSIXklHwIDAQAB
-----END RSA PUBLIC KEY-----"""

        # Handshake
        self.create_auth_key()
        print(self.auth_key)
        print(self.server_salt)

    """
    g = public (prime) base, known to Alice, Bob, and Eve. g = 5
    p = public (prime) number, known to Alice, Bob, and Eve. p = 23
    a = Alice's private key, known only to Alice. a = 6
    b = Bob's private key known only to Bob. b = 15
    """

    def dh_exhange_initiation(self):
        # 1) Client sends query to server
        self._req_pq()

    def _req_pq(self):
        nonce = tl.int128(self.random.getrandbits(128))
        request = tl.req_pq(nonce)
        self.send_message(request.to_bytes())
        res_pq = tl.ResPQ.from_stream(self.recv_message())

        assert nonce.value == res_pq.nonce.value

        return res_pq

    def create_auth_key(self):

        # resPQ#05162463 nonce:int128 server_nonce:int128 pq:bytes server_public_key_fingerprints:Vector<long> = ResPQ;
        resPQ = self._req_pq()

        public_key_fingerprint = resPQ.server_public_key_fingerprints.items[0]
        pq = int.from_bytes(resPQ.pq.value, 'big')

        [p, q] = prime.primefactors(pq)
        (p, q) = (q, p) if p > q else (p, q)  # q must be > p, put in right order
        assert p * q == pq and p < q

        print("Factorization %d = %d * %d" % (pq, p, q))

        p_bytes = long_to_bytes(p)
        q_bytes = long_to_bytes(q)
        key = RSA.importKey(self.rsa_key)
        new_nonce = os.urandom(32)

        assert False, "TODO: Working up to here"

        p_q_inner_data = rpc.p_q_inner_data(pq=resPQ.pq, p=p_bytes, q=q_bytes,
                                            server_nonce=resPQ.server_nonce,
                                            nonce=resPQ.nonce,
                                            new_nonce=new_nonce)

        data = p_q_inner_data.get_bytes()
        assert p_q_inner_data.nonce == resPQ.nonce

        sha_digest = SHA.new(data).digest()
        # get padding of random data to fill what is left after data and sha_digest
        random_bytes = os.urandom(255 - len(data) - len(sha_digest))
        to_encrypt = sha_digest + data + random_bytes  # encrypt cat of sha_digest, data, and padding
        encrypted_data = key.encrypt(to_encrypt, 0)[0]  # rsa encrypt (key == RSA.key)

        # Presenting proof of work; Server authentication
        req_DH_params = rpc.req_DH_params(p=p_bytes, q=q_bytes,
                                          nonce=resPQ.nonce,
                                          server_nonce=resPQ.server_nonce,
                                          public_key_fingerprint=public_key_fingerprint,
                                          encrypted_data=encrypted_data)
        data = req_DH_params.get_bytes()

        self.send_message(data)
        data = self.recv_message(debug=False)

        # 5) Server responds in one of two ways:
        server_DH_params = rpc.server_DH_params(data)
        assert resPQ.nonce == server_DH_params.nonce
        assert resPQ.server_nonce == server_DH_params.server_nonce

        encrypted_answer = server_DH_params.encrypted_answer

        tmp_aes_key = SHA.new(new_nonce + resPQ.server_nonce).digest()
        tmp_aes_key += SHA.new(resPQ.server_nonce + new_nonce).digest()[0:12]

        tmp_aes_iv = SHA.new(resPQ.server_nonce + new_nonce).digest()[12:20]
        tmp_aes_iv = tmp_aes_iv + SHA.new(new_nonce + new_nonce).digest() + new_nonce[0:4]

        answer_with_hash = crypt.ige_decrypt(encrypted_answer, tmp_aes_key, tmp_aes_iv)
        #                           ^--- decrypting here

        # answer_hash = answer_with_hash[:20]
        answer = answer_with_hash[20:]  # decrypted at this point

        # server_DH_inner_data#b5890dba nonce:int128 server_nonce:int128 g:int dh_prime:string g_a:string server_time:int = Server_DH_inner_data;
        server_DH_inner_data = rpc.server_DH_inner_data(answer)
        assert resPQ.nonce == server_DH_inner_data.nonce
        assert resPQ.server_nonce == server_DH_inner_data.server_nonce

        dh_prime_str = server_DH_inner_data.dh_prime
        g = server_DH_inner_data.g
        g_a_str = server_DH_inner_data.g_a
        server_time = server_DH_inner_data.server_time
        self.timedelta = server_time - time()  # keep in mind delta is used somewhere later

        dh_prime = bytes_to_long(dh_prime_str)
        g_a = bytes_to_long(g_a_str)

        assert prime.isprime(dh_prime)
        retry_id = 0
        b_str = os.urandom(256)
        b = bytes_to_long(b_str)
        g_b = pow(g, b, dh_prime)

        g_b_str = long_to_bytes(g_b)

        client_DH_inner_data = rpc.client_DH_inner_data(
            nonce=resPQ.nonce,
            server_nonce=resPQ.server_nonce,
            retry_id=retry_id,
            g_b=g_b_str)

        data = client_DH_inner_data.get_bytes()

        data_with_sha = SHA.new(data).digest() + data
        data_with_sha_padded = data_with_sha + os.urandom(-len(data_with_sha) % 16)
        encrypted_data = crypt.ige_encrypt(data_with_sha_padded, tmp_aes_key, tmp_aes_iv)

        for i in range(1, self.AUTH_MAX_RETRY):  # retry when dh_gen_retry or dh_gen_fail
            set_client_DH_params = rpc.set_client_DH_params(
                nonce=resPQ.nonce,
                server_nonce=resPQ.server_nonce,
                encrypted_data=encrypted_data)
            self.send_message(set_client_DH_params.get_bytes())
            Set_client_DH_params_answer = rpc.set_client_DH_params_answer(self.recv_message())

            # print Set_client_DH_params_answer
            auth_key = pow(g_a, b, dh_prime)
            auth_key_str = long_to_bytes(auth_key)
            auth_key_sha = SHA.new(auth_key_str).digest()
            auth_key_aux_hash = auth_key_sha[:8]

            new_nonce_hash1 = SHA.new(new_nonce+b'\x01'+auth_key_aux_hash).digest()[-16:]
            new_nonce_hash2 = SHA.new(new_nonce+b'\x02'+auth_key_aux_hash).digest()[-16:]
            new_nonce_hash3 = SHA.new(new_nonce+b'\x03'+auth_key_aux_hash).digest()[-16:]

            assert Set_client_DH_params_answer.nonce == resPQ.nonce
            assert Set_client_DH_params_answer.server_nonce == resPQ.server_nonce

            if Set_client_DH_params_answer.status == 'ok':
                assert Set_client_DH_params_answer.new_nonce_hash == new_nonce_hash1
                print("Diffie Hellman key exchange processed successfully")

                self.server_salt = strxor(new_nonce[0:8], resPQ.server_nonce[0:8])
                self.auth_key = auth_key_str
                self.auth_key_id = auth_key_sha[-8:]
                print("Auth key generated")
                return "Auth Ok"
            elif Set_client_DH_params_answer.status == 'retry':
                assert Set_client_DH_params_answer.new_nonce_hash == new_nonce_hash2
                print("Retry Auth")
            elif Set_client_DH_params_answer.status == 'fail':
                assert Set_client_DH_params_answer.new_nonce_hash == new_nonce_hash3
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

    def send_message(self, message_data):  # package message, not chat message
        # stage 1
        # first one (e.g. req_PQ) message_data == constructor + 16 bytes
        message_id = self.generate_message_id()
        message = (b'\x00\x00\x00\x00\x00\x00\x00\x00' +  # 8 nulls means unencrypted
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

    def recv_message(self, debug=False):
        """
        Reading socket and receiving message from server. Check the CRC32.
        """
        if debug:
            packet = self.sock.recv(1024)  # reads how many bytes to read
            hexdump(packet)

        packet_length_data = self.socket.read(4)  # reads how many bytes to read

        if len(packet_length_data) < 4:
            raise Exception("Nothing in the socket!")
        packet_length = struct.unpack("<I", packet_length_data)[0]
        packet = self.socket.read(packet_length - 4)  # read the rest of bytes from socket

        # check the CRC32
        if not crc32(packet_length_data + packet[0:-4]) == struct.unpack('<I', packet[-4:])[0]:
            raise Exception("CRC32 was not correct!")
        # x = struct.unpack("<I", packet[:4])
        auth_key_id = packet[4:12]
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
        MTProto('FFFFFFFFF', 'EEEEEEEE')
