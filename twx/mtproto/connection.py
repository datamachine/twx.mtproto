import struct
import asyncio

from enum import Enum

from . util import crc32
from . import tl


class MTProtoConnection:

    class ConnectionType(str, Enum):
        TCP = 'TCP'

    TCP = ConnectionType.TCP

    def __new__(cls, connection_type=None):
        if cls is MTProtoConnection:
            connection_type = cls.ConnectionType(connection_type)
            if connection_type is cls.ConnectionType.TCP:
                return object.__new__(MTProtoTCPConnection)
        else:
            super().__new__(cls)


class MTProtoTCPConnection(asyncio.Protocol, MTProtoConnection):

    def __init__(self, connection_type):
        self.seq_no = 0

    def connection_made(self, transport):
        self.transport = transport

    def data_recieved(self, data):
        print(data)

    def connection_lost(self, exc):
        print('The server closed the connection')

    def send_message(self, mtproto_msg):
        payload = mtproto_msg
        header_and_payload = bytes().join([
            int.to_bytes(len(payload) + 12, 4, 'little'),
            int.to_bytes(self.seq_no, 4, 'little'),
            payload
            ])
        crc = tl.int_c._to_bytes(crc32(header_and_payload))

        self.transport.write(header_and_payload + crc)

@asyncio.coroutine
def test_connection(conn):
    conn.send_message(b'test\n')

if __name__ == '__main__':
    conn = MTProtoConnection('TCP')
    loop = asyncio.get_event_loop()
    coro = loop.create_connection(lambda: conn, '127.0.0.1', 8888)

    server = loop.run_until_complete(coro)
    server = loop.run_until_complete(test_connection(conn))
    loop.run_forever()
    loop.close()
