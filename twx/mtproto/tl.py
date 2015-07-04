from abc import ABCMeta, abstractmethod, abstractstaticmethod
from collections import namedtuple
from functools import partial
from enum import Enum

from . util import to_hex, crc32

import sys

import logging

from io import IOBase, BytesIO

log = logging.getLogger(__name__)


"""
---types---
"""


class TLObject(metaclass=ABCMeta):

    __slots__ = ()

    def __bytes__(self):
        return self.to_bytes()

    def to_bytes(self):
        return b''.join(self._bytes())

    def hex_components(self):
        return ' '.join([to_hex(data) for data in self._bytes()])

    @abstractmethod
    def _bytes(self):
        """A list of bytes() (one item for each component of the combinator)"""
        raise NotImplementedError()


_IntBase = namedtuple('int', 'value')
_LongBase = namedtuple('long', 'value')
_DoubleBase = namedtuple('double', 'value')
_StringBase = namedtuple('String', 'value')

_Int128Base = namedtuple('Int128', 'value')
_Int256Base = namedtuple('Int256', 'value')

_ResPQBase = namedtuple('ResPQ', ['nonce', 'server_nonce', 'pq', 'server_public_key_fingerprints'])

_VectorBase = namedtuple('Vector', ('type', 'count', 'items'))


class TLType:

    def __new__(cls, *args, **kwargs):
        raise SyntaxError("Do not use this class directly, call from_stream")

    @classmethod
    def from_stream(cls, stream, *args):
        """Boxed type combinator loading"""
        con_num = stream.read(4)
        con = cls.constructors.get(con_num)
        if con is None:
            raise ValueError('{} does not have combinator with number {}'.format(cls, to_hex(con_num)))

        return con.from_stream(stream, *args)

    @classmethod
    def add_constuctor(cls, constructor_cls):
        if not hasattr(cls, 'constructors'):
            setattr(cls, 'constructors', {})
        cls.constructors[constructor_cls.number] = constructor_cls


Int = type('Int', (TLType,), {})
Long = type('Long', (TLType,), {})
Double = type('Double', (TLType,), {})
String = type('String', (TLType,), {})

Vector = type('Vector', (TLType,), {})

Int128 = type('Int128', (TLType,), {})
Int256 = type('Int256', (TLType,), {})

ResPQ = type('ResPQ', (TLType,), {})


"""
---constructors---
"""


class TLCombinator(TLObject):

    @abstractstaticmethod
    def from_stream(stream, boxed):
        raise NotImplementedError()

    def to_boxed_bytes(self):
        return b''.join([self.number, self.to_bytes()])

    def to_hex(self, width=4, boxed=False):
        if boxed:
            return to_hex(self.to_boxed_bytes(), width)
        return to_hex(self.to_bytes(), width)


class TLConstructor(TLCombinator):
    ...


class long(_LongBase, TLConstructor):

    """
    int ? = Int
    """

    __slots__ = ()

    number = crc32('long ? = long'.encode()).to_bytes(4, 'little')

    def _bytes(self):
        return [self.value.to_bytes(8, 'little')]

    @staticmethod
    def from_int(_int):
        result = long.__new__(long, _int)
        return result

    @staticmethod
    def from_stream(stream):
        return long.from_int(int.from_bytes(stream.read(8), byteorder='little'))
Long.add_constuctor(long)


class vector(_VectorBase, TLConstructor):

    number = int(0x1cb5c415).to_bytes(4, 'little')

    def _bytes(self):
        return [item.to_bytes() for item in self.items]

    @staticmethod
    def from_stream(stream, item_type):
        count = int.from_bytes(stream.read(4), 'little')
        items = []
        for i in iter(range(count)):
            items.append(item_type.from_stream(stream))
        return vector.__new__(vector, item_type, count, items)
Vector.add_constuctor(vector)


class int128(_Int128Base, TLConstructor):

    """
    int ? = Int
    """

    __slots__ = ()

    number = crc32('int 4*[ int ] = Int128'.encode()).to_bytes(4, 'little')

    def _bytes(self):
        return [self.value.to_bytes(16, 'little')]

    @staticmethod
    def from_int(_int):
        result = int128.__new__(int128, _int)
        return result

    @staticmethod
    def from_stream(stream, boxed=False):
        return int128.from_int(int.from_bytes(stream.read(16), byteorder='little'))


class string(_StringBase, TLConstructor):

    def __str__(self):
        return self.value.encode()

    def _bytes(self):
        str_bytes = bytes(self.value)

        length = len(str_bytes)
        if length <= 253:
            length = length.to_bytes(1, byteorder='little')
        else:
            length = b''.join(int(254).to_bytes(1, byteorder='little'),
                              length.to_bytes(3, byteorder='little'))

        padding = bytes(4 - (len(length) + len(str_bytes)) % 4)

        return [length + str_bytes + padding]

    @staticmethod
    def from_stream(stream):
        count = 0

        str_len = int.from_bytes(stream.read(1), 'little')
        count += 1

        if str_len > 253:
            str_len = int.from_bytes(stream.read(3), 'little')
            count += 3

        str_bytes = stream.read(str_len)
        count += str_len

        # get rid of the padded bytes
        stream.read(4 - count % 4)

        return string.__new__(string, str_bytes)


class resPQ(_ResPQBase, TLConstructor):

    """
    resPQ#05162463 nonce:int128 server_nonce:int128 pq:string
                   server_public_key_fingerprints:Vector long = ResPQ
    """

    number = int(0x05162463).to_bytes(4, 'little')

    __slot__ = ()

    @staticmethod
    def from_stream(stream):
        nonce = int128.from_stream(stream)
        server_nonce = int128.from_stream(stream)
        pq = string.from_stream(stream)
        server_public_key_fingerprints = Vector.from_stream(stream, long)

        return resPQ.__new__(resPQ, nonce, server_nonce, pq, server_public_key_fingerprints)

    def _bytes(self, boxed=False):
        result = [self.number] if boxed else []
        return result + self.nonce._bytes() + self.server_nonce._bytes() + self.pq._bytes() + self.server_public_key_fingerprints._bytes()

ResPQ.add_constuctor(resPQ)


"""
---functions---
"""


class TLFunction(TLCombinator):

    @abstractmethod
    def _bytes(self):
        """all functions must return boxed bytes (i.e. the start with their combinator number)"""
        raise NotImplementedError()


class req_pq(namedtuple('req_pq', ['nonce', 'result_type']), TLCombinator):

    """req_pq#60469778 nonce:int128 = ResPQ"""

    number = int(0x60469778).to_bytes(4, byteorder='little')

    def __new__(cls, nonce, result_type=resPQ):
        return super(req_pq, cls).__new__(cls, nonce, result_type)

    def _bytes(self):
        return [req_pq.number] + self.nonce._bytes()

