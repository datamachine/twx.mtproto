import asyncio

from enum import Enum
from abc import ABCMeta
from struct import Struct
from urllib.parse import urlsplit

from .util import crc32
from .coretypes import MTProtoCRCMismatchError
from . import scheme


class MTProtoTransport(metaclass=ABCMeta):

    class _TYPE(str, Enum):
        HTTP = 'HTTP'
        UDP = 'UDP'
        TCP = 'TCP'
        TCP_INTERMEDIATE = 'TCP_INTERMEDIATE'
        TCP_ABRIDGED = 'TCP_ABRIDGED'

    HTTP = _TYPE.HTTP
    UDP = _TYPE.UDP
    TCP = _TYPE.TCP
    TCP_INTERMEDIATE = _TYPE.TCP_INTERMEDIATE
    TCP_ABRIDGED = _TYPE.TCP_ABRIDGED

    def __new__(cls, transport_type, *args, **kwargs):
        if cls is MTProtoTransport:
            transport_type = MTProtoTransport._TYPE(transport_type)

            transport_cls = NotImplemented
            if transport_type == MTProtoTransport.TCP:
                transport_cls = TCPTransport

            return transport_cls(*args, **kwargs)
        raise NotImplementedError()


class TCPTransport(asyncio.Protocol):
    """
    int32 packet_length | int32 seq_no | bytes message | int32 crc32
    """

    _header_struct = Struct('<II')
    _crc32_struct = Struct('<I')

    def __init__(self):
        super().__init__()
        self._seq_no = 0
        self._connected = False
        self._transport = None
        self._received_messages = asyncio.Queue()

    def connection_made(self, transport):
        print('connection_made')
        self._transport = transport
        self._connected = True

    def data_received(self, data):
        print('data_received:', data)

    def connection_lost(self, exc):
        pass

    def pre_process(self, data):
        packet_length = scheme.int32_c(12 + len(data)).get_bytes()
        seq_no = scheme.int32_c(self._seq_no).get_bytes()

        tcp_msg = bytes().join((packet_length, seq_no, data,))

        crc = scheme.int32_c(crc32(tcp_msg)).get_bytes()

        tcp_msg += crc

        return tcp_msg

    def post_process(self, data):
        view = memoryview(data)
        length, seq_no = self._header_struct.unpack_from(view)
        crc = self._crc32_struct.unpack_from(view[length-4:])
        if crc != crc32(view[0:length-4]):
            raise MTProtoCRCMismatchError()
        return view[8:-4]

    @asyncio.coroutine
    def send(self, mtproto_msg):
        data = self.pre_process(mtproto_msg)

        while not self._connected:
            print(self._connected)
            yield from asyncio.sleep(1)

        print('send:', data)

        self._transport.write(data)

    def run(self):
        while True:
            pass

MTProtoTransport.register(TCPTransport)
