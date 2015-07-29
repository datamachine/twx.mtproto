import asyncio

from enum import Enum
from collections import namedtuple, OrderedDict
from struct import Struct

from . import scheme
from .util import to_hex, crc32


class MTProtoUnencryptedMessage(
    namedtuple('MTProtoUnencryptedMessage', 'auth_key_id message_id message_data_length message_data')):

    """
    Unencrypted Message:
        auth_key_id = 0:int64   message_id:int64   message_data_length:int32   message_data:bytes
    """

    _header_struct = Struct('<QQI')

    def __new__(cls, message_id, message_data):
        return super().__new__(cls, scheme.int64_c(0), scheme.int64_c(message_id), scheme.int32_c(len(message_data)), message_data)

    @classmethod
    def new(cls, message_id, message_data):
        message_data = message_data.get_bytes()
        return cls(scheme.int64_c(message_id), message_data)

    def buffers(self):
        return self.auth_key_id.buffers() + self.message_id.buffers() + self.message_data_length.buffers() + [self.message_data]

    def get_bytes(self):
        return b''.join(self.buffers())

    @classmethod
    def from_bytes(cls, data):
        auth_key_id, message_id, message_data_length = cls._header_struct.unpack(data[0:20])
        return super().__new__(cls, auth_key_id, message_id, message_data_length, data[20:])


class MTProtoTCPMessage(namedtuple('MTProtoTCPMessage', 'data')):

    @classmethod
    def new(cls, seq_no, mtproto_msg):
        payload = mtproto_msg.get_bytes()

        header_and_payload = bytes().join([
            scheme.int32_c(len(payload) + 12).get_bytes(),
            scheme.int32_c(seq_no).get_bytes(),
            payload
            ])

        crc = scheme.int32_c(crc32(header_and_payload)).get_bytes()

        return cls(header_and_payload + crc)

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

    def is_encrypted(self):
        return self.payload[0:8] != b'\x00\x00\x00\x00\x00\x00\x00\x00'


    @property
    def crc(self):
        return int.from_bytes(self.data[-4:], 'little')

    def crc_ok(self):
        return self.crc == crc32(self.data[:-4])

    def get_bytes(self):
        return self.data

    def get_message(self):
        if self.is_encrypted():
            raise NotImplementedError()
        else:
            return MTProtoUnencryptedMessage.from_bytes(self.payload)


class ConnectionType(str, Enum):
    TCP = 'TCP'
    # UDP = 'UDP'
    # HTTP = 'HTTP'


class MTProtoClientProtocol(asyncio.Protocol):

    def __init__(self):
        self._ingress = asyncio.Queue()
        self._egress = asyncio.Queue()
        self.last_msg_id = 0

    @classmethod
    def new(cls, connection_type):
        if cls is MTProtoClientProtocol:
            connection_type = ConnectionType(connection_type)
            if connection_type is ConnectionType.TCP:
                return MTProtoTCPClientProtocol()

        raise NotImplementedError()

    @asyncio.coroutine
    def send_insecure_message(self, msg):
        raise NotImplementedError()

    @asyncio.coroutine
    def get_message(self):
        result = yield from self._ingress.get()
        return result

    @asyncio.coroutine
    def send_insecure_message(self, msg):
        message_id = generate_message_id(self.last_msg_id)
        mtproto_msg = MTProtoUnencryptedMessage.new(message_id, msg)
        self.last_msg_id = message_id
        print('send_insecure_message', msg)
        yield from self._egress.put(mtproto_msg)

    @asyncio.coroutine
    def send_encrypted_message(self, msg):
        yield from self._egress.put(msg)

    def create_connection(self, *args, **kwargs):
        raise NotImplementedError()


class MTProtoTCPClientProtocol(MTProtoClientProtocol):

    def __init__(self):
        super().__init__()
        self._seq_no = 0
        self._tcp_egress = asyncio.Queue()
        self.transport = None

    def create_connection(self, host, port, loop):
        return loop.create_connection(lambda: self, host, port)

    def connection_made(self, transport):
        self.transport = transport
        print('connection_made:', self.transport)

    def data_received(self, data):
        tcp_msg = MTProtoTCPMessage.from_bytes(data)
        if tcp_msg.crc_ok():
            self._ingress.put_nowait(tcp_msg.get_message())
            # print(self._ingress)

    def connection_lost(self, exc):
        print('connection_lost:', exc)

    @asyncio.coroutine
    def handle_egress(self):
        while True:
            while self.transport is None:
                yield from asyncio.sleep(0.1)

            mtproto_msg = yield from self._egress.get()
            print('handle_egress:', mtproto_msg)
            tcp_msg = MTProtoTCPMessage.new(self._seq_no, mtproto_msg)
            self._seq_no += 1
            yield from self._tcp_egress.put(tcp_msg)
            self.transport.write(tcp_msg.get_bytes())


def generate_message_id(last_msg_id):
    from time import time

    msg_id = int(time() * 2**32)
    if last_msg_id > msg_id:
        msg_id = last_msg_id + 1
    while msg_id % 4 is not 0:
        msg_id += 1

    return msg_id


@asyncio.coroutine
def create_auth_key_test(connection, loop):
    from random import SystemRandom
    rand = SystemRandom()

    req_pq = scheme.req_pq(nonce=rand.getrandbits(128))
    yield from connection.send_insecure_message(req_pq)
    print('waiting for response')
    response = yield from connection.get_message()
    print('response:', response)


if __name__ == '__main__':

    loop = asyncio.get_event_loop()

    conn = MTProtoClientProtocol.new('TCP')

    coro = conn.create_connection('149.154.167.40', 443, loop=loop)

    asyncio.async(coro, loop=loop)
    asyncio.async(conn.handle_egress(), loop=loop)
    asyncio.async(create_auth_key_test(conn, loop), loop=loop)

    loop.run_forever()
