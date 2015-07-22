from abc import ABCMeta, abstractmethod, abstractstaticmethod
from collections import namedtuple
from functools import partial
from enum import Enum
from collections import OrderedDict, UserList
from struct import Struct

from . util import to_hex, crc32

import sys

import logging

from io import IOBase, BytesIO

log = logging.getLogger(__name__)


"""
---types---
"""





def encoded_combinator_number(data):
    """
    converts a string represenation of a combinator into a bytes represenation of its number

    ::
        # vector#1cb5c415 {t:Type} # [ t ] = Vector t
        encoded_combinator_number('vector type:t # [ t ] = Vector') -> b'\x15\xc4\xb5\x1c'
    """
    if isinstance(data, str):
        data = data.encode()
    return crc32(data).to_bytes(4, 'little')

class TLObject(metaclass=ABCMeta):

    __slots__ = ()

    def to_bytes(self):
        return b''.join(self.to_buffers())

    def hex_components(self):
        return ' '.join([to_hex(data) for data in self.to_buffers()])

    @abstractmethod
    def to_buffers(self):
        """A list of bytes() (one item for each component of the combinator)"""
        raise NotImplementedError()


_VectorBase = namedtuple('Vector', ('t', 'num', 'items'))


class TLType:
    constructors = {}

    def __new__(cls, *args, **kwargs):
        raise SyntaxError('TLType is not to be created standalone')

    @classmethod
    def from_stream(cls, stream):
        """Boxed type combinator loading"""
        con_num = stream.read(4)
        con = cls.constructors.get(con_num)
        if con is None:
            if cls is TLType:
                raise ValueError('constructor with number {} does not exists'.format(to_hex(con_num)))
            else:
                raise ValueError('{} does not have combinator with number {}'.format(cls, to_hex(con_num)))

        return con.from_stream(stream)

    @classmethod
    def add_constuctor(cls, constructor_cls):
        if TLType.constructors.get(constructor_cls.number) is not None:
            raise ValueError('duplicate constructor with number: {}'.format(constructor_cls.number))
        TLType.constructors[constructor_cls.number] = constructor_cls
        cls.constructors[constructor_cls.number] = constructor_cls

_P_Q_inner_dataBase = namedtuple('P_Q_inner_data', ['pq', 'p', 'q', 'nonce', 'server_nonce', 'new_nonce'])
P_Q_inner_data = type('P_Q_inner_data', (TLType,), dict(constructors={}))


"""
---constructors---
"""


class TLCombinator(TLObject):

    def hex_components(self, boxed=False):
        result = ['{}:{}'.format(self.name, to_hex(self.number, 4))] if boxed else ['{}: '.format(self.name)]
        for arg in self:
            result += ['{}:{}'.format(arg.name, to_hex(b''.join(arg.to_buffers()), 4))]
        return " ".join(result)

    @abstractstaticmethod
    def from_stream(stream, boxed):
        raise NotImplementedError()

    def to_boxed_bytes(self):
        return b''.join([self.number, self.to_bytes()])

    def to_hex(self, width=4, boxed=False):
        if boxed:
            return to_hex(self.to_boxed_bytes(), width)
        return to_hex(self.to_bytes(), width)

    def to_buffers(self):
        raise NotImplementedError()


class TLConstructor(TLCombinator):

    def to_buffers(self, boxed=False):
        result = [self.number] if boxed else []
        for arg in self:
            result += arg.to_buffers()
        return result

    @classmethod
    def from_stream(cls, stream):
        args = []
        for p in cls.param_types:
            arg = p.from_stream(stream)
            args.append(arg)
        return cls.__new__(cls, *args)

def create_constructor(name, number, params, param_types, result_type):
    def con__new__(cls, *args, **kwargs):
        return super(cls._cls, cls).__new__(cls, *args, **kwargs)

    params = namedtuple(name, params)
    class_bases = (params, TLConstructor, result_type,)
    class_body = dict(
        __new__=con__new__,
        name=name,
        number=number.to_bytes(4, 'little'),
        params=params,
        param_types=params(*list(param_types)),
        result_type=result_type
        )
    new_type = type(name, class_bases, class_body)
    setattr(new_type, '_cls', new_type)

    result_type.add_constuctor(new_type)
    return new_type

class _IntBase(int):

    def __new__(cls, value):
        return cls.from_int(value)

    @classmethod
    def from_int(cls, value):
        result = int.__new__(cls, value)
        if result.bit_length() > cls._bit_length:
            raise ValueError('{:d} cannot fit into a {}bit Integer'.format(result, cls._bit_length))
        return result

    @classmethod
    def from_bytes(cls, data):
        value = int.from_bytes(data, 'little')
        return cls.from_int(value)

    @classmethod
    def from_stream(cls, stream):
        data = stream.read(cls._byte_length)
        if len(data) < cls._byte_length:
            raise StreamReadError('{} requires {:d} bytes, only read {:d}'.format(cls, cls._byte_length, len(data)))
        return cls.from_bytes(data)

    @classmethod
    def _to_bytes(cls, value):
        return int.to_bytes(value, cls._byte_length, 'little')

    def to_bytes(self):
        return int.to_bytes(self, self._byte_length, 'little')

    def to_buffers(self):
        return [self.to_bytes()]


class Int(_IntBase, TLType):
    constructors = {}

    _bit_length = 32
    _byte_length = 4

class int_c(Int, TLConstructor):

    """
    int ? = Int
    """
    __slots__ = ()

    number = encoded_combinator_number('int ? = Int')
    name = 'int'

Int.add_constuctor(int_c)


class Long(_IntBase, TLType):
    constructors = {}

    _bit_length = 64
    _byte_length = 8

class long_c(Long, TLConstructor):

    """
    long ? = Long
    """
    __slots__ = ()

    number = encoded_combinator_number('long ? = Long')
    name = 'long'
Long.add_constuctor(long_c)

int64_c = long_c  # utility alias


class Double(int, TLType):
    constructors = {}

    def __new__(cls, value):
        if isinstance(value, bytes):
            return double_c.from_bytes()

        return double_c.from_float(float(value))


class double_c(Double, TLConstructor):

    """
    double ? = Double
    """
    __slots__ = ()

    number = encoded_combinator_number('double ? = Double')
    name = 'double'
    _struct = Struct('<d')

    def to_buffers(self):
        return [self.to_bytes()]

    def to_bytes(self):
        return self._struct.pack(self)

    @classmethod
    def from_bytes(cls, data):
        value = cls._struct.unpack(data)[0]
        return float.__new__(cls, value)

    @classmethod
    def from_float(cls, value):
        return float.__new__(cls, value)

    @classmethod
    def from_stream(cls, stream):
        return cls.from_bytes(stream.read(8))
Double.add_constuctor(double_c)


class Vector(UserList, TLType):

    constructors = {}

    _vector_types = {}

    def __new__(cls, *args, **kwargs):
        if cls is Vector or cls is vector_c:
            vector_item_cls = args[0] if args else kwargs.get('vector_item_cls')
            if not issubclass(vector_item_cls, TLType):
                raise TypeError('vector_item_cls must be a subclass of TLType')
            key = (cls, vector_item_cls,)
            vector_cls = cls._vector_types.get(key)
            if vector_cls is None:
                name = '{}_{}'.format(cls.__name__, vector_item_cls.__name__)
                Vector._vector_types[key] = type(name, (cls,), {'_item_cls_':vector_item_cls})
                vector_cls = Vector._vector_types.get(key)
                print('creating new vector type {}'.format(vector_cls))
            return vector_cls
        else:
            return object.__new__(cls)

    def __init__(self, initlist=None):
        super().__init__(map(self._item_cls_, initlist))

    def insert(self, index, item):
        return super().insert(index, self._item_cls_(item))

    def append(self, item):
        return super().append(self._item_cls_(item))

    def extend(self, iterable):
        return super().extend(map(self._item_cls_, iterable))

    def __setitem__(self, index, item):
        return super().__setitem__(index, self._item_cls_(item))

    def __add__(self, iterable):
        return super().__add__(map(self._item_cls_, iterable))

    def __iadd__(self, iterable):
        return super().__iadd__(map(self._item_cls_, iterable))

    @classmethod
    def _from_stream(cls, stream):
        num = int.from_bytes(stream.read(4), 'little')
        items = []
        for i in iter(range(num)):
            items.append(cls._item_cls_.from_stream(stream))
        return cls(items)
    
    @classmethod
    def from_stream(cls, stream):
        """Boxed type combinator loading"""
        con_num = stream.read(4)
        con = cls.constructors.get(con_num)
        if con is None:
            raise ValueError('{} does not have combinator with number {}'.format(cls, to_hex(con_num)))

        return cls._from_stream(stream)

    def _to_bytes(self):
        count = len(self).to_bytes(4, 'little')
        items = [i.to_bytes() for i in self.data]
        return b''.join([count] + items)

    def to_bytes(self, boxed=True):
        return vector_c.number + self._to_bytes()

class vector_c(Vector, TLConstructor):

    number = int(0x1cb5c415).to_bytes(4, 'little')
    name = 'vector'

    def to_buffers(self):
        return [item.to_bytes() for item in self.items]

    @classmethod
    def from_stream(cls, stream):
        return cls._from_stream(stream)

    def to_bytes(self):
        return self._to_bytes()
Vector.add_constuctor(vector_c)


class Int128(_IntBase, TLType):
    constructors = {}

    _bit_length = 128
    _byte_length = 16

class int128_c(Int128, TLConstructor):

    """
    int128 4*[ int ] = Int128
    """

    number = encoded_combinator_number('int 4*[ int ] = Int128')
    name = 'int128'
Int128.add_constuctor(int128_c)


class Int256(_IntBase, TLType):
    constructors = {}

    _bit_length = 256
    _byte_length = 32

class int256_c(Int256, TLConstructor):

    """
    int256 8*[ int ] = Int256
    """

    number = encoded_combinator_number('int 8*[ int ] = Int256')
    name = 'int256'
Int256.add_constuctor(int256_c)


class String(bytes, TLType):
    constructors = {}

    def __new__(cls, data):
        return cls.from_bytes(data)

    @classmethod
    def from_stream(cls, stream):
        str_len = stream.read(1)[0]
        count = 1

        if str_len == 254:
            str_len = int.from_bytes(stream.read(3), 'little')
            count += 3

        data = stream.read(str_len)
        count += str_len

        # get rid of the padded bytes
        stream.read((4 - (count % 4)) % 4)

        return cls.from_bytes(data)

    @classmethod
    def from_int(cls, value, byteorder='little', length=None):
        if length is None:
            length = value.bit_length() // 8 + 1

        return cls.from_bytes(value.to_bytes(length, byteorder))

    @classmethod
    def from_bytes(cls, data):
        return bytes.__new__(cls, data)

    @classmethod
    def from_str(cls, string):
        return str.__new__(cls, string, encoding='utf-8')

    def to_bytes(self):
        str_len = len(self)

        pfx = bytes([str_len]) if str_len < 254 else bytes([254]) + str_len.to_bytes(3, 'little')

        padding = bytes((4 - (len(pfx) + len(self)) % 4) % 4)

        return b''.join([pfx, self, padding])

    def to_buffers(self):
        return [self.to_bytes()]

    def to_int(self, byteorder='little'):
        return int.from_bytes(self, byteorder)

class string_c(String, TLConstructor):

    number = encoded_combinator_number('string ? = String')
    name = 'string'


class bytes_c(string_c):

    name = 'bytes'

class ResPQ(namedtuple('ResPQ', ['nonce', 'server_nonce', 'pq', 'server_public_key_fingerprints']), TLType):
    constructors = {}

class resPQ_c(TLConstructor, ResPQ):
    """
    resPQ#05162463 nonce:int128 server_nonce:int128 pq:bytes server_public_key_fingerprints:Vector<long> = ResPQ;
    """
    number = b'\x63\x24\x16\x05'
    name = 'resPQ_c'

    @classmethod
    def from_stream(cls, stream):
        return tuple.__new__(cls, [
            int128_c.from_stream(stream),
            int128_c.from_stream(stream),
            bytes_c.from_stream(stream),
            Vector(long_c).from_stream(stream)
            ])

ResPQ.add_constuctor(resPQ_c)


class P_Q_inner_data(TLType):
    constructors = {}


p_q_inner_data_c = create_constructor(
    name='p_q_inner_data_c', number=0x83c95aec,
    params=['pq', 'p', 'q', 'nonce', 'server_nonce', 'new_nonce'],
    param_types=[bytes_c, bytes_c, bytes_c, int128_c, int128_c, int256_c],
    result_type=P_Q_inner_data)


class Server_DH_Params(TLType, namedtuple('Server_DH_Params',
    ['nonce', 'server_nonce', 'new_nonce_hash', 'encrypted_answer'])):
    constructors = {}

    def __new__(cls, nonce, server_nonce, new_nonce_hash, encrypted_answer):
        raise SyntaxError('Do not call Server_DH_Params directly')


class server_DH_params_fail_c(TLConstructor, Server_DH_Params):

    """
    server_DH_params_fail#79cb045d nonce:int128 server_nonce:int128 new_nonce_hash:int128 = Server_DH_Params;
    """
    number = b'\x5dx\04\xcb\x79'
    name = 'server_DH_params_fail_c'

    def __new__(cls, nonce, server_nonce, new_nonce_hash):
        return tuple.__new__(cls, [int128_c(nonce), int128_c(server_nonce), int128_c(new_nonce_hash), None])

    @classmethod
    def from_stream(cls, stream):
        return tuple.__new__(cls, [
            int128_c.from_stream(stream),
            int128_c.from_stream(stream),
            int128_c.from_stream(stream),
            None
            ])

class server_DH_params_ok_c(TLConstructor, Server_DH_Params):

    """
    server_DH_params_ok#d0e8075c nonce:int128 server_nonce:int128 encrypted_answer:bytes = Server_DH_Params;
    """
    number = b'\x5c\x07\xe8\xd0'
    name = 'server_DH_params_ok_c'

    def __new__(cls, nonce, server_nonce, encrypted_answer):
        return tuple.__new__(cls, [int128_c(nonce), int128_c(server_nonce), None, bytes_c(encrypted_answer)])

    @classmethod
    def from_stream(cls, stream):
        return tuple.__new__(cls, [
            int128_c.from_stream(stream),
            int128_c.from_stream(stream),
            None,
            bytes_c.from_stream(stream)
            ])

Server_DH_Params.add_constuctor(server_DH_params_fail_c)
Server_DH_Params.add_constuctor(server_DH_params_ok_c)


class Server_DH_inner_data(TLType):
    constructors = {}


server_DH_inner_data_c = create_constructor(
    name='server_DH_inner_data_c', number=0xb5890dba,
    params=['nonce', 'server_nonce', 'g', 'dh_prime', 'g_a', 'server_time'],
    param_types=[int128_c, int128_c, int_c, bytes_c, bytes_c, int_c],
    result_type=Server_DH_inner_data)


class Client_DH_Inner_Data(TLType):
    constructors = {}


client_DH_inner_data_c = create_constructor(
    name='client_DH_inner_data_c', number=0x6643b654,
    params=['nonce', 'server_nonce', 'retry_id', 'g_b'],
    param_types=[int128_c, int128_c, long_c, bytes_c],
    result_type=Client_DH_Inner_Data)


class Set_client_DH_params_answer(TLType):
    constructors = {}


dh_gen_ok_c = create_constructor(
    name='dh_gen_ok_c', number=0x3bcbf734,
    params=['nonce', 'server_nonce', 'new_nonce_hash1'],
    param_types=[int128_c, int128_c, int128_c],
    result_type=Set_client_DH_params_answer)


dh_gen_retry_c = create_constructor(
    name='dh_gen_retry_c', number=0x46dc1fb9,
    params=['nonce', 'server_nonce', 'new_nonce_hash2'],
    param_types=[int128_c, int128_c, int128_c],
    result_type=Set_client_DH_params_answer)


dh_gen_fail_c = create_constructor(
    name='dh_gen_fail_c', number=0xa69dae02,
    params=['nonce', 'server_nonce', 'new_nonce_hash3'],
    param_types=[int128_c, int128_c, int128_c],
    result_type=Set_client_DH_params_answer)


class RpcResult(TLType):
    constructors = {}


rpc_result_c = create_constructor(
    name='rpc_result_c', number=0xf35c6d01,
    params=['req_msg_id', 'result'],
    param_types=[long_c, TLType],
    result_type=RpcResult)


class RpcError(TLType):
    constructors = {}


rpc_error_c = create_constructor(
    name='rpc_error_c', number=0x2144ca19,
    params=['error_code', 'error_message'],
    param_types=[int_c, string_c],
    result_type=RpcError)


class RpcDropAnswer(TLType):
    constructors = {}


rpc_answer_unknown_c = create_constructor(
    name='rpc_answer_unknown_c', number=0x5e2ad36e,
    params=[],
    param_types=[],
    result_type=RpcDropAnswer)


rpc_answer_dropped_running_c = create_constructor(
    name='rpc_answer_dropped_running_c', number=0xcd78e586,
    params=[],
    param_types=[],
    result_type=RpcDropAnswer)


rpc_answer_dropped_c = create_constructor(
    name='rpc_answer_dropped_c', number=0xa43ad8b7,
    params=['msg_id', 'seq_no', 'bytes'],
    param_types=[long_c, int_c, int_c],
    result_type=RpcDropAnswer)


class FutureSalt(TLType):
    constructors = {}


future_salt_c = create_constructor(
    name='future_salt_c', number=0x0949d9dc,
    params=['valid_since', 'valid_until', 'salt'],
    param_types=[int_c, int_c, long_c],
    result_type=FutureSalt)


class FutureSalts(TLType):
    constructors = {}


future_salts_c = create_constructor(
    name='future_salts_c', number=0xae500895,
    params=['req_msg_id', 'now', 'salts'],
    param_types=[long_c, int_c, vector_c(future_salt_c)],
    result_type=FutureSalts)


class Pong(TLType):
    constructors = {}


pong_c = create_constructor(
    name='pong_c', number=0x347773c5,
    params=['msg_id', 'ping_id'],
    param_types=[long_c, long_c],
    result_type=Pong)


class DestroySessionRes(TLType):
    constructors = {}


destroy_session_ok_c = create_constructor(
    name='destroy_session_ok_c', number=0xe22045fc,
    params=['session_id'],
    param_types=[long_c],
    result_type=DestroySessionRes)


destroy_session_none_c = create_constructor(
    name='destroy_session_none_c', number=0x62d350c9,
    params=['session_id'],
    param_types=[long_c],
    result_type=DestroySessionRes)


class NewSession(TLType):
    constructors = {}


new_session_created_c = create_constructor(
    name='new_session_created_c', number=0x9ec20908,
    params=['first_msg_id', 'unique_id', 'server_salt'],
    param_types=[long_c, long_c, long_c],
    result_type=NewSession)


class Message(TLType):
    constructors = {}


message_c = create_constructor(
    name='message_c', number=crc32('message msg_id:long seqno:int bytes:int body:Object = Message'.encode()),
    params=['msg_id', 'seqno', 'bytes', 'body'],
    param_types=[long_c, int_c, int_c, TLType],
    result_type=Message)


class MessageContainer(TLType):
    constructors = {}


msg_container_c = create_constructor(
    name='msg_container_c', number=0x73f1f8dc,
    params=['messages'],
    param_types=[vector_c(message_c)],
    result_type=MessageContainer)


class MessageCopy(TLType):
    constructors = {}


msg_copy_c = create_constructor(
    name='msg_copy_c', number=0xe06046b2,
    params=['orig_message'],
    param_types=[Message],
    result_type=MessageCopy)


gzip_packed_c = create_constructor(
    name='gzip_packed_c', number=0x3072cfa1,
    params=['packed_data'],
    param_types=[bytes_c],
    result_type=TLType)


class MsgsAck(TLType):
    constructors = {}


msgs_ack_c = create_constructor(
    name='msgs_ack_c', number=0x62d6b459,
    params=['msg_ids'],
    param_types=[Vector(long_c)],
    result_type=MsgsAck)


class BadMsgNotification(TLType):
    constructors = {}


bad_msg_notification_c = create_constructor(
    name='bad_msg_notification_c', number=0xa7eff811,
    params=['bad_msg_id', 'bad_msg_seqno', 'error_code'],
    param_types=[long_c, int_c, int_c],
    result_type=BadMsgNotification)


bad_server_salt_c = create_constructor(
    name='bad_server_salt_c', number=0xedab447b,
    params=['bad_msg_id', 'bad_msg_seqno', 'error_code', 'new_server_salt'],
    param_types=[long_c, int_c, int_c, long_c],
    result_type=BadMsgNotification)


class MsgResendReq(TLType):
    constructors = {}


msg_resend_req_c = create_constructor(
    name='msg_resend_req_c', number=0x7d861a08,
    params=['msg_ids'],
    param_types=[Vector(long_c)],
    result_type=MsgResendReq)


class MsgsStateReq(TLType):
    constructors = {}


msgs_state_req_c = create_constructor(
    name='msgs_state_req_c', number=0xda69fb52,
    params=['msg_ids'],
    param_types=[Vector(long_c)],
    result_type=MsgsStateReq)


class MsgsStateInfo(TLType):
    constructors = {}


msgs_state_info_c = create_constructor(
    name='msgs_state_info_c', number=0x04deb57d,
    params=['req_msg_id', 'info'],
    param_types=[long_c, bytes_c],
    result_type=MsgsStateInfo)


class MsgsAllInfo(TLType):
    constructors = {}


msgs_all_info_c = create_constructor(
    name='msgs_all_info_c', number=0x8cc0d131,
    params=['msg_ids', 'info'],
    param_types=[Vector(long_c), bytes_c],
    result_type=MsgsAllInfo)


class MsgDetailedInfo(TLType):
    constructors = {}


msg_detailed_info_c = create_constructor(
    name='msg_detailed_info_c', number=0x276d3ec6,
    params=['msg_id', 'answer_msg_id', 'bytes', 'status'],
    param_types=[long_c, long_c, int_c, int_c],
    result_type=MsgDetailedInfo)



"""
---functions---
"""


class TLFunction(TLCombinator):

    def to_buffers(self):
        result = [self.number]
        for arg in self:
            result += arg.to_buffers()
        return result


class req_pq(namedtuple('req_pq', ['nonce']), TLFunction):

    """req_pq#60469778 nonce:int128 = ResPQ"""

    number = int(0x60469778).to_bytes(4, byteorder='little')
    name = 'req_DH_params'
    ...


class req_DH_params(namedtuple('req_DH_params',
    ['nonce', 'server_nonce', 'p', 'q', 'public_key_fingerprint', 'encrypted_data']), TLFunction):

    """
    req_DH_params#d712e4be nonce:int128 server_nonce:int128 p:string q:string public_key_fingerprint:long encrypted_data:string = Server_DH_Params
    """
    number = int(0xd712e4be).to_bytes(4, byteorder='little')
    name = 'req_DH_params'
    ...

class set_client_DH_params(namedtuple('set_client_DH_params', ['nonce', 'server_nonce', 'encrypted_data']), TLFunction):

    """
    set_client_DH_params#f5045f1f nonce:int128 server_nonce:int128 encrypted_data:bytes = Set_client_DH_params_answer
    """
    number = int(0xf5045f1f).to_bytes(4, byteorder='little')
    name = 'set_client_DH_params'
    ...


"""
--main api testing--
"""

"""
nearestDc#8e1a1775 country:string this_dc:int nearest_dc:int = NearestDc;
help.getNearestDc#1fb33026 = NearestDc;
"""
class NearestDc(TLType):
    constructors = {}

nearestDC_c = create_constructor(
    name='nearestDC', number=0x8e1a1775,
    params=['country', 'this_dc', 'nearest_dc'],
    param_types=[string_c, int_c, int_c],
    result_type=NearestDc)

class help_getNearestDc(namedtuple('getNearestDc', []), TLFunction):
    number = int(0x1fb33026).to_bytes(4, 'little')
    name = 'getNearestDc'
    result_type = NearestDc
