from abc import ABCMeta, abstractmethod, abstractstaticmethod
from collections import namedtuple
from functools import partial
from enum import Enum
from collections import OrderedDict

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


_VectorBase = namedtuple('Vector', ('t', 'num', 'items'))


class TLType:

    def __new__(cls, *args, **kwargs):
        if issubclass(cls, Vector):
            return super(TLType, cls).__new__(cls)

        raise SyntaxError("Do not use this class directly, call from_stream")


    @classmethod
    def from_stream(cls, stream):
        print(cls, ...)
        """Boxed type combinator loading"""
        con_num = stream.read(4)
        con = cls.constructors.get(con_num)
        if con is None:
            raise ValueError('{} does not have combinator with number {}'.format(cls, to_hex(con_num)))

        return con.from_stream(stream)

    @classmethod
    def add_constuctor(cls, constructor_cls):
        if not hasattr(cls, 'constructors'):
            setattr(cls, 'constructors', {})
        cls.constructors[constructor_cls.number] = constructor_cls


Int = type('Int', (TLType,), {})
Long = type('Long', (TLType,), {})
Double = type('Double', (TLType,), {})
String = type('String', (TLType,), {})


class Vector(TLType):

    __slots__ = ('t')

    def __new__(cls, t):
        result = super(Vector, cls).__new__(cls, allow_new=True)
        result.t = t
        return result

    def __init__(self, t):
        pass

    def from_stream(self, stream):
        """Boxed type combinator loading"""
        con_num = stream.read(4)
        con = self.constructors.get(con_num)
        if con is None:
            raise ValueError('{} does not have combinator with number {}'.format(self, to_hex(con_num)))

        return con.from_stream(stream, self.t)


_P_Q_inner_dataBase = namedtuple('P_Q_inner_data', ['pq', 'p', 'q', 'nonce', 'server_nonce', 'new_nonce'])
P_Q_inner_data = type('P_Q_inner_data', (TLType,), {})


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

    def _bytes(self):
        raise NotImplementedError()


class TLConstructor(TLCombinator):

    def _bytes(self, boxed=False):
        result = [self.number] if boxed else []
        for arg in self:
            result += arg._bytes()
        return result

    @classmethod
    def from_stream(cls, stream):
        args = [p.from_stream(stream) for p in cls.param_types]
        return cls.__new__(cls, *args)

def create_constructor(name, number, params, param_types, result_type):
    params = namedtuple(name, params)
    class_bases = (params, TLConstructor)
    class_body = dict(
        name=name,
        number=number.to_bytes(4, 'little'),
        params=params,
        param_types=params(*list(param_types)),
        result_type=result_type
        )
    new_type = type(name, class_bases, class_body)
    result_type.add_constuctor(new_type)
    return new_type

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

    @classmethod
    def from_stream(cls, stream):
        return long.from_int(int.from_bytes(stream.read(8), byteorder='little'))
Long.add_constuctor(long)


class vector(_VectorBase, TLConstructor):

    number = int(0x1cb5c415).to_bytes(4, 'little')

    def _bytes(self):
        return [item.to_bytes() for item in self.items]

    @staticmethod
    def from_stream(stream, t):
        print('building', ...)
        num = int.from_bytes(stream.read(4), 'little')
        items = []
        for i in iter(range(num)):
            items.append(t.from_stream(stream))
        return vector.__new__(vector, t, num, items)
Vector.add_constuctor(vector)

"""
int128 4*[ int ] = Int128
int256 8*[ int ] = Int256
"""
_Int128Base = namedtuple('Int128', 'value')
_Int256Base = namedtuple('Int256', 'value')
Int128 = type('Int128', (TLType,), {})
Int256 = type('Int256', (TLType,), {})

class int128(_Int128Base, TLConstructor):

    number = crc32('int 4*[ int ] = Int128'.encode()).to_bytes(4, 'little')

    def _bytes(self):
        return [self.value.to_bytes(16, 'little')]

    @staticmethod
    def from_int(_int):
        result = int128.__new__(int128, _int)
        return result

    @classmethod
    def from_stream(cls, stream, boxed=False):
        return int128.from_int(int.from_bytes(stream.read(16), byteorder='little'))

class int256(_Int128Base, TLConstructor):

    number = crc32('int 4*[ int ] = Int128'.encode()).to_bytes(4, 'little')

    def _bytes(self):
        return [self.value.to_bytes(32, 'little')]

    @staticmethod
    def from_int(_int):
        result = int128.__new__(int128, _int)
        return result

    @classmethod
    def from_stream(cls, stream, boxed=False):
        return int128.from_int(int.from_bytes(stream.read(32), byteorder='little'))
Int256.add_constuctor(int256)


class string(_StringBase, TLConstructor):

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

    @classmethod
    def from_stream(cls, stream):
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

    @staticmethod
    def from_bytes(obj):
        assert isinstance(obj, bytes)

        len_pfx = len(obj)
        if len_pfx < 254:
            len_pfx = len_pfx.to_bytes(1, 'little')
        else:
            len_pfx = int(254).to_bytes(1, 'little') + len_pfx.to_bytes(3, 'little')

        padding = bytes(4 - (len(len_pfx) + len(obj)) % 4)

        value = b''.join([len_pfx, obj, padding])
        assert len(value) % 4 == 0

        return string.__new__(string, value)

    @staticmethod
    def from_int(obj, length, byteorder, signed=False):
        assert isinstance(obj, int)
        return string.from_bytes(obj.to_bytes(length, byteorder, signed=signed))

"""
type: ResPQ
constructors:
    resPQ#05162463 nonce:int128 server_nonce:int128 pq:string server_public_key_fingerprints:Vector long = ResPQ
"""
ResPQ = type('ResPQ', (TLType,), {})

resPQ = create_constructor(
    name='resPQ', number=0x05162463,
    params=['nonce', 'server_nonce', 'pq', 'server_public_key_fingerprints'],
    param_types=[int128, int128, string, Vector(long)],
    result_type=ResPQ)

"""
type: P_Q_inner_data
constructors:
    p_q_inner_data#83c95aec pq:string p:string q:string nonce:int128 server_nonce:int128 new_nonce:int256 = P_Q_inner_data
    p_q_inner_data_temp#3c6a84d4 pq:string p:string q:string nonce:int128 server_nonce:int128 new_nonce:int256 expires_in:int = P_Q_inner_data;
"""
P_Q_inner_data = type('P_Q_inner_data', (TLType,), dict())

p_q_inner_data = create_constructor(
    name='p_q_inner_data', number=0x83c95aec,
    params=['pq', 'p', 'q', 'nonce', 'server_nonce', 'new_nonce'],
    param_types=[string, string, string, int128, int128, int256],
    result_type=P_Q_inner_data)

p_q_inner_data_temp = create_constructor(
    name='p_q_inner_data_temp', number=0x3c6a84d4,
    params=['pq', 'p', 'q', 'nonce', 'server_nonce', 'new_nonce', 'expires_in'],
    param_types=[string, string, string, int128, int128, int256, int],
    result_type=P_Q_inner_data)


"""
---functions---
"""


class TLFunction(TLCombinator):

    def _bytes(self):
        result = [self.number]
        for arg in self:
            result += arg._bytes()
        return result


class req_pq(namedtuple('req_pq', ['nonce']), TLFunction):

    """req_pq#60469778 nonce:int128 = ResPQ"""

    number = int(0x60469778).to_bytes(4, byteorder='little')
    ...


class req_DH_params(namedtuple('req_DH_params',
    ['nonce', 'server_nonce', 'p', 'q', 'public_key_fingerprint', 'encrypted_data'])):

    """
    req_DH_params#d712e4be nonce:int128 server_nonce:int128 p:string q:string public_key_fingerprint:long encrypted_data:string = Server_DH_Params
    """
    ...