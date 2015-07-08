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




_VectorBase = namedtuple('Vector', ('t', 'num', 'items'))


class TLType:
    constructors = {}

    def __new__(cls, *args, **kwargs):
        if issubclass(cls, Vector):
            return super(TLType, cls).__new__(cls)

        raise SyntaxError("Do not use this class directly, call from_stream")

    @classmethod
    def from_stream(cls, stream):
        """Boxed type combinator loading"""
        con_num = stream.read(4)
        con = cls.constructors.get(con_num)
        if con is None:
            raise ValueError('{} does not have combinator with number {}'.format(cls, to_hex(con_num)))

        return con.from_stream(stream)

    @classmethod
    def add_constuctor(cls, constructor_cls):
        if TLType.constructors.get(constructor_cls.number) is not None:
            raise ValueError('duplicate constructor with number: {}'.format(constructor_cls.number))
        cls.constructors[constructor_cls.number] = constructor_cls




class Vector(TLType):

    constructors = {}

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
P_Q_inner_data = type('P_Q_inner_data', (TLType,), dict(constructors={}))


"""
---constructors---
"""


class TLCombinator(TLObject):

    def hex_components(self, boxed=False):
        result = ['{}:{}'.format(self.name, to_hex(self.number, 4))] if boxed else ['{}: '.format(self.name)]
        for arg in self:
            result += ['{}:{}'.format(arg.name, to_hex(b''.join(arg._bytes()), 4))]
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

    def _bytes(self):
        raise NotImplementedError()

    @classmethod
    def verify_arg_types(cls, *args, **kwargs):
        for arg, param_type in zip(args, cls.param_types):
            if isinstance(param_type, TLType):
                if arg.number not in param_type.constructors:
                    raise TypeError('{}:{} is not a constructor for {}, must be one of {}'.format(arg, arg.number, param_type, param_type.constructors.keys()))

            elif not isinstance(arg, param_type):
                raise TypeError('{}:{} should be {} in {}'.format(arg, type(arg), param_type, cls))

        for key, arg in kwargs.items():
            param_type = cls.param_types._asdict()[key]
            if not isinstance(arg, param_type) and not issubclass(arg, param_type):
                raise TypeError('{}:{} should be {} in {}'.format(arg, type(arg), param_type, self))


class TLConstructor(TLCombinator):

    def _bytes(self, boxed=False):
        result = [self.number] if boxed else []
        for arg in self:
            result += arg._bytes()
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
        cls.verify_arg_types(*args, **kwargs)
        return super(cls._cls, cls).__new__(cls, *args, **kwargs)

    params = namedtuple(name, params)
    class_bases = (params, TLConstructor)
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

_IntBase = namedtuple('int', 'value')
_LongBase = namedtuple('long', 'value')
_DoubleBase = namedtuple('double', 'value')
_StringBase = namedtuple('String', 'value')

Int = type('Int', (TLType,), dict(constructors={}))
Long = type('Long', (TLType,), dict(constructors={}))
Double = type('Double', (TLType,), dict(constructors={}))
String = type('String', (TLType,), dict(constructors={}))

class int_c(_IntBase, TLConstructor):

    """
    int ? = Int
    """

    __slots__ = ()

    number = crc32('int ? = Int'.encode()).to_bytes(4, 'little')
    name='int'

    def _bytes(self):
        return [self.value.to_bytes(4, 'little')]

    @staticmethod
    def from_int(_int):
        result = int_c.__new__(int_c, _int)
        return result

    @classmethod
    def from_stream(cls, stream):
        return int_c.from_int(int.from_bytes(stream.read(4), byteorder='little'))
Int.add_constuctor(int_c)

class long_c(_LongBase, TLConstructor):

    """
    int ? = Int
    """

    __slots__ = ()

    number = crc32('long ? = Long'.encode()).to_bytes(4, 'little')
    name = 'long_c'

    def _bytes(self):
        return [self.value.to_bytes(8, 'little')]

    @staticmethod
    def from_int(_int):
        result = long_c.__new__(long_c, _int)
        return result

    @classmethod
    def from_stream(cls, stream):
        return long_c.from_int(int.from_bytes(stream.read(8), byteorder='little'))
Long.add_constuctor(long_c)


class vector_c(_VectorBase, TLConstructor):

    number = int(0x1cb5c415).to_bytes(4, 'little')
    name = 'vector'

    def __new__(cls, item_type, num=None, items=None):
        return super().__new__(cls, item_type, num, items)

    def _bytes(self):
        return [item.to_bytes() for item in self.items]

    @staticmethod
    def from_stream(stream, t):
        num = int.from_bytes(stream.read(4), 'little')
        items = []
        for i in iter(range(num)):
            items.append(t.from_stream(stream))
        return vector_c.__new__(vector_c, t, num, items)
Vector.add_constuctor(vector_c)

"""
int128 4*[ int ] = Int128
int256 8*[ int ] = Int256
"""
Int128 = type('Int128', (TLType,), dict(constructors={}))
Int256 = type('Int256', (TLType,), dict(constructors={}))

_Int128Base = namedtuple('Int128', 'value')
_Int256Base = namedtuple('Int256', 'value')

class int128_c(_Int128Base, TLConstructor):

    number = crc32('int 4*[ int ] = Int128'.encode()).to_bytes(4, 'little')
    param_types = _Int128Base(int)
    name = 'int128'

    def _bytes(self):
        return [self.value.to_bytes(16, 'little')]

    @staticmethod
    def from_int(_int):
        result = int128_c.__new__(int128_c, _int)
        return result

    @classmethod
    def from_bytes(cls, obj):
        return int128_c.from_int(int.from_bytes(obj, byteorder='little'))

    @classmethod
    def from_stream(cls, stream, boxed=False):
        return int128_c.from_int(int.from_bytes(stream.read(16), byteorder='little'))

class int256_c(_Int128Base, TLConstructor):

    number = crc32('int 4*[ int ] = Int128'.encode()).to_bytes(4, 'little')
    param_types = _Int128Base(int)

    def _bytes(self):
        return [self.value.to_bytes(32, 'little')]

    @staticmethod
    def from_int(_int):
        result = int128_c.__new__(int128_c, _int)
        return result

    @classmethod
    def from_stream(cls, stream, boxed=False):
        return int128_c.from_int(int.from_bytes(stream.read(32), byteorder='little'))
Int256.add_constuctor(int256_c)


class string_c(_StringBase, TLConstructor):

    name = 'string'
    param_types = _StringBase(bytes)

    def pfx(self):
        length = len(self.value)
        if length < 254:
            return bytes([length])
        else:
            return b''.join([bytes([254]), length.to_bytes(3, 'little')])

    def pfx_length(self):
        return len(self.pfx())

    def value_length(self):
        return len(self.value)

    def padding(self):
        return bytes(self.padding_length())

    def padding_length(self):
        return (4 - ((self.pfx_length() + self.value_length()) % 4)) % 4

    def total_length(self):
        print(self.pfx_length(), self.value_length(), self.padding_length(), ...)
        return self.pfx_length() + self.value_length() + self.padding_length()

    def _bytes(self):
        return [self.pfx() + self.value + self.padding()]

    @classmethod
    def from_stream(cls, stream):
        str_len = stream.read(1)[0]
        count = 1

        if str_len > 253:
            str_len = int.from_bytes(stream.read(3), 'little', signed=True)
            count += 3

        str_bytes = stream.read(str_len)
        count += str_len

        # get rid of the padded bytes
        stream.read((4 - (count % 4)) % 4)

        return string_c.__new__(string_c, str_bytes)

    @staticmethod
    def from_bytes(obj):
        assert isinstance(obj, bytes)

        return string_c.__new__(string_c, obj)

    @staticmethod
    def from_int(obj, length=None, byteorder='little'):
        assert isinstance(obj, int)

        if length is None:
            length = obj.bit_length() // 8 + 1

        return string_c.from_bytes(obj.to_bytes(length, byteorder))

    def to_int(self, byteorder='little'):
        return int.from_bytes(self.value, byteorder)

bytes_c = string_c



class ResPQ(TLType):
    constructors = {}


resPQ_c = create_constructor(
    name='resPQ_c', number=0x05162463,
    params=['nonce', 'server_nonce', 'pq', 'server_public_key_fingerprints'],
    param_types=[int128_c, int128_c, bytes_c, Vector(long_c)],
    result_type=ResPQ)


class P_Q_inner_data(TLType):
    constructors = {}


p_q_inner_data_c = create_constructor(
    name='p_q_inner_data_c', number=0x83c95aec,
    params=['pq', 'p', 'q', 'nonce', 'server_nonce', 'new_nonce'],
    param_types=[bytes_c, bytes_c, bytes_c, int128_c, int128_c, int256_c],
    result_type=P_Q_inner_data)


class Server_DH_Params(TLType):
    constructors = {}


server_DH_params_fail_c = create_constructor(
    name='server_DH_params_fail_c', number=0x79cb045d,
    params=['nonce', 'server_nonce', 'new_nonce_hash'],
    param_types=[int128_c, int128_c, int128_c],
    result_type=Server_DH_Params)


server_DH_params_ok_c = create_constructor(
    name='server_DH_params_ok_c', number=0xd0e8075c,
    params=['nonce', 'server_nonce', 'encrypted_answer'],
    param_types=[int128_c, int128_c, bytes_c],
    result_type=Server_DH_Params)


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

    def _bytes(self):
        result = [self.number]
        for arg in self:
            result += arg._bytes()
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
