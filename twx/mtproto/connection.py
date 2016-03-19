import struct
import asyncio
import logging
import struct
import time

from enum import Enum
from collections import namedtuple
from io import BytesIO
from urllib.parse import urlsplit


try:
    from . util import crc32, to_hex
    from . import tl
    from . import scheme
except SystemError:
    from util import crc32, to_hex
    import tl
    import scheme


log = logging.getLogger(__name__)

class MTProtoConnection:

    class ConnectionType(str, Enum):
        TCP = 'TCP'

    TCP = ConnectionType.TCP

    def __new__(cls, *args, **kwargs):
        if cls is MTProtoConnection:
            raise SyntaxError('do not call this directly')
        else:
            return object.__new__(cls, *args, **kwargs)

    def __init__(self):
        self.seq_no = 0
        self.transport = None
        self.received_messages = dict()

    @classmethod
    def new(cls, connection_type):
        if cls is MTProtoConnection:
            connection_type = cls.ConnectionType(connection_type)
            if connection_type is cls.ConnectionType.TCP:
                return MTProtoTCPConnection()
            else:
                raise TypeError()
        else:
            return MTProtoConnection.__new__(cls)

    def received_mtproto_data(self, mtp_msg):
        response = tl.TLType.from_stream(BytesIO(mtp_msg.message_data))
        log.debug('    content: {}'.format(response))

        self.received_messages[mtp_msg.message_id] = response

    @asyncio.coroutine
    def get_message(self, message_id):
        count = 500
        for i in iter(range(count)):
            msg = self.received_messages.get(message_id)
            if msg is not None:
                return msg
            time.sleep(0.1)

    def send_insecure_message(self, message_id, request):
        # package message, not chat message
        log.debug('sending request:'
                  '\n    message_id: {}'
                  '\n    request:    {}'.format(message_id, request))
        msg = MTProtoUnencryptedMessage.new(message_id, request)

        self.send_message(msg)


class MTProtoTCPMessage(namedtuple('MTProtoTCPMessage', 'data')):

    @classmethod
    def new(cls, seq_no, mtproto_msg):
        payload = mtproto_msg.get_bytes()
        # print('payload:', payload)
        # print(to_hex(scheme.int32_c(len(payload) + 12).get_bytes()))

        header_and_payload = bytes().join([
            scheme.int32_c(len(payload) + 12).get_bytes(),
            scheme.int32_c(seq_no).get_bytes(),
            payload
            ])

        crc = scheme.int32_c(crc32(header_and_payload)).get_bytes()

        return cls(header_and_payload + crc)

    @classmethod
    def from_stream(cls, stream):
        length_bytes = stream.read(4)
        length = int.from_bytes(length_bytes, 'little')

        return cls(length_bytes + stream.read(length))

    @classmethod
    def from_bytes(cls, data):
        length = int.from_bytes(data[0:4], 'little')
        return cls(data[:length+4])

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


class MTProtoMessage:

    @classmethod
    def from_tcp_msg(cls, tcp_msg):
        if tcp_msg.payload[0:8] == b'\x00\x00\x00\x00\x00\x00\x00\x00':
            return MTProtoUnencryptedMessage.from_tcp_msg(tcp_msg)
        else:
            return MTProtoEncryptedMessage.from_tcp_msg(tcp_msg)

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

        _header_struct = struct.Struct('<QQQII')
    
        @classmethod
        def new(cls, salt, session_id, message_id, seq_no, message_data):
            return cls(salt, session_id, message_id, seq_no, len(message_data), message_data)

        def generate_padding(self):
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
        unencryped_data += self.encrypted_data.generate_padding()

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

class EmptyValue:

    def __new__(cls):
        raise SyntaxError()


class MTProtoUnencryptedMessage(MTProtoMessage,
    namedtuple('MTProtoUnencryptedMessage', 'auth_key_id message_id message_data_length message_data')):

    """
    Unencrypted Message:
        auth_key_id = 0:int64   message_id:int64   message_data_length:int32   message_data:bytes
    """

    _header_struct = struct.Struct('<QQI')

    @classmethod
    def new(cls, message_id, message_data):
        return cls.__new__(cls, scheme.int64_c(0), scheme.int64_c(message_id), EmptyValue, message_data)

    def buffers(self):
        message_data = self.message_data.buffers()
        message_data_length = scheme.int32_c(sum([len(data) for data in message_data]))
        # message_data_length = scheme.int32_c(message_data_length)
        return self.auth_key_id.buffers() + self.message_id.buffers() + message_data_length.buffers() + message_data

    def hex_list(self):
        return [to_hex(buf, 0) for buf in self.buffers()]

    def get_bytes(self):
        return b''.join(self.buffers())

    @classmethod
    def from_tcp_msg(cls, tcp_msg):
        return cls.from_bytes(tcp_msg.payload)

    @classmethod
    def from_bytes(cls, data):
        auth_key_id, message_id, message_data_length = cls._header_struct.unpack(data[0:20])
        return cls(auth_key_id, message_id, message_data_length, data[20:])


class MTProtoTCPConnection(asyncio.Protocol):

    def connection_made(self, transport):
        self.transport = transport


class TCPConnection:

    def __init__(self, host, port):
        self.queue = None
        self.host = host
        self.port = port

    @asyncio.coroutine
    def run(self, loop):
        self.queue = asyncio.Queue(loop=loop)
        reader, writer = yield from asyncio.open_connection(self.host, self.port, loop=loop)

        seq_no = 0

        while True:
            data = yield from self.queue.get()
            print(data.hex_list())

            tcp_msg = MTProtoTCPMessage.new(seq_no, data)
            print(tcp_msg)
            writer.write(tcp_msg.data)
            yield from writer.drain()

            rec_data_length_bytes = yield from reader.read(4)
            rcv_data_length = int.from_bytes(rec_data_length_bytes, 'little')

            rcv_data = yield from reader.read(rcv_data_length - 4)
            rcv_msg = MTProtoTCPMessage.from_bytes(rec_data_length_bytes + rcv_data)
            print(rcv_msg)

            yield from asyncio.sleep(1)

    @asyncio.coroutine
    def debug(self, loop):
        while True:
            print(self.queue.qsize())
            yield from asyncio.sleep(1)

    @asyncio.coroutine
    def send_insecure_message(self, message_id, obj):
        mtproto_msg = MTProtoUnencryptedMessage.new(message_id, obj)
        yield from self.queue.put(mtproto_msg)


if __name__ == '__main__':
    con = TCPConnection('127.0.0.1', 8888)

    loop = asyncio.get_event_loop()
    asyncio.async(con.run(loop))
    asyncio.async(con.debug(loop))

    loop.run_forever()
    loop.close()
