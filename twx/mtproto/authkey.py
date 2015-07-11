from collections import namedtuple

from . coretypes import MTProtoKeyNotReadyError
from . crypt import SHA1, RSA2048Key, AES256Key, ige_encrypt, ige_decrypt
from . util import substr

def _aes_encrypt(data, aes_key, aes_iv):
    return ige_encrypt(data, aes_key, aes_iv)

def aes_encrypt(data, auth_key, msg_key):
    aes_key, aes_iv = auth_key.prepare_aes(msg_key)
    return _aes_encrypt(data, aes_key, aes_iv)

def _aes_decrypt(data, aes_key, aes_iv):
    return ige_decrypt(data, aes_key, aes_iv)

def aes_decrypt(data, auth_key, msg_key):
    aes_key, aes_iv = auth_key.prepare_aes(msg_key, True)
    return _aes_decrypt(data, aes_key, aes_iv)

def aes_encrypt_local(data, auth_key, msg_key):
    aes_key, aes_iv = auth_key.prepare_aes(msg_key, False)
    return _aes_encrypt(data, aes_key, aes_iv)

class MTProtoAuthKey:

    def __init__(self):
        self._dc = None
        self._key_id = None
        self._key = None

    def set_key(self, key):
        self._key = RSA2048Key(key)
        self._key_id = SHA1(self._key)[-8:]

    def created(self):
        return self._key_id is not None

    @property
    def dc(self):
        return self._dc
    
    @dc.setter
    def dc(self, dc):
        self._dc = dc

    @property
    def key_id(self):
        if not self.created():
            raise MTProtoKeyNotReadyError("key_id")

        return self._key_id

    def prepare_aes(self, msg_key, from_server=False):
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

        auth_key = self._key

        # TelegramDesktop uses condition "x = 8 if send else 0"
        # But that seems in contradiction to the statement above
        x = 8 if from_server else 0

        sha1_a = SHA1(msg_key + substr(auth_key, x, 32))
        sha1_b = SHA1(substr(auth_key, 32+x, 16) + msg_key + substr(auth_key, 48+x, 16))
        sha1_с = SHA1(substr(auth_key, 64+x, 32) + msg_key)
        sha1_d = SHA1(msg_key + substr(auth_key, 96+x, 32))
        aes_key = substr(sha1_a, 0, 8) + substr(sha1_b, 8, 12) + substr(sha1_с, 4, 12)
        aes_iv = substr(sha1_a, 8, 12) + substr(sha1_b, 0, 8) + substr(sha1_с, 16, 4) + substr(sha1_d, 0, 8)

        return AES256Key(aes_key), AES256Key(aes_iv)
