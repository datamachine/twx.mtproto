from collections import namedtuple
from collections import UserList
from struct import Struct
from functools import partial

from util import crc32

class MTProtoKeyNotReadyError(Exception):
    pass

class StreamReadError(Exception):
    pass

def generate_number(string):
    """
    converts a string represenation of a combinator into its number

    ::
        # vector#1cb5c415 {t:Type} # [ t ] = Vector t
        generate_number('vector type:t # [ t ] = Vector') -> 0x1cb5c415
    """
    return int_c(crc32(string.encode()))

class MTPType:

    __slots__ = ()

    def __new__(cls, name):
        if cls is MTPType:
            return type(name, (MTPType,), dict(_constructors={}))
        raise NotImplementedError()

class BareType:

    def __new__(cls, *args, **kwargs):
        if cls is BareType:
            return cls._type_factory(*args, **kwargs)

        return cls._make(*args, **kwargs)

    @staticmethod
    def _type_factory(name, number, params, param_types, result_type):
        param_tuple = namedtuple(name, params)
        param_types = param_tuple(*param_types)

        attrs = dict(
            number=int_c(number),
            param_types=param_types,
            )

        bare_type = type(name, (BareType, param_tuple, result_type,), attrs)
        result_type._constructors[bare_type.number] = bare_type
        return bare_type

    @classmethod
    def _make(cls, *args, **kwargs):
        
        len_args = len(args)
        result_args = []
        i = 0
        for param, param_type in cls.param_types._asdict().items():
            value = args[i] if i < len_args else kwargs[param]
            result_args.append(param_type(value))
            i += 1

        return super()._make(result_args)

    def buffers(self):
        bufs = list()
        for value in self:
            bufs.extend(value.buffers())
        return bufs

    def get_bytes(self):
        return b''.join(self.buffers())

    def hex_list(self):
        """ returns of strings list of all individual elements converted to bytes and formatted in hex """
        return [''.join(['{:02X}'.format(b) for b in data]) for data in self.buffers()]

class BoxedType:

    _base_boxed_types = {}
    _boxed_types = {}

    def __new__(cls, bare_obj):
        boxed_type = cls._get_boxed_type(type(bare_obj))

        return tuple.__new__(boxed_type, bare_obj)

    @staticmethod
    def new(name, result_type):
        return BoxedType._boxed_base_type_factory(name, result_type)

    @staticmethod
    def _boxed_base_type_factory(name, result_type):
        return BoxedType._base_boxed_types.setdefault(name, type(name, (BoxedType, result_type,), dict(name=name)))

    @classmethod
    def _get_boxed_type(cls, bare_type):
        return cls._boxed_types.setdefault(bare_type.number, cls._boxed_type_factory(bare_type))

    @classmethod
    def _boxed_type_factory(cls, bare_type):
        return type(cls.name, (cls, bare_type,), dict())

    def buffers(self):
        return self.number.buffers() + super().buffers()


class int_c(int):

    """
    int ? = Int
    """
    __slots__ = ()

    number = 'int ? = Int'

    _struct = Struct('<I')

    def buffers(self):
        return [int_c._struct.pack(self)]
int_c.number = generate_number(int_c.number)

int32_c = int_c  # alias for general utility


class long_c(int):

    __slots__ = ()

    number = generate_number('long ? = Long')

    _struct = Struct('<Q')

    def buffers(self):
        return [long_c._struct.pack(self)]

int64_c = long_c  # alias for general utility


class int128_c(int):

    number = generate_number('int 4*[ int ] = Int128')

    def buffers(self):
        return [self.to_bytes(16, 'little')]


class int256_c(int):

    number = generate_number('int 8*[ int ] = Int256')

    def buffers(self):
        return [self.to_bytes(32, 'little')]


class double_c(float):

    """
    double ? = Double
    """
    __slots__ = ()

    number = generate_number('double ? = Double')

    _struct = Struct('<d')

    def buffers(self):
        return [double_c._struct.pack(self)]


# overriding string_c intentionally so that there are not lingering objects in the namespace
string_c = namedtuple('string_c', 'prefix data padding')
class string_c(BareType, string_c):

    number = generate_number('string ? = String')

    class _prefix(bytes):

        @classmethod
        def new(cls, data):
            length = len(data)
            return bytes.__new__(cls, bytes([length]) if length < 254 else b'\xfe' + length.to_bytes(3, 'little'))

        def buffers(self):
            return [self]

        def get_bytes(self):
            return self

    class _data(bytes):

        @classmethod
        def new(cls, data):
            if isinstance(data, str):
                data = bytes(data, 'utf-8')
            return bytes.__new__(cls, data)

        def buffers(self):
            return [self]

        def get_bytes(self):
            return self

    class _padding(bytes):

        @classmethod
        def new(cls, prefix, data):
            length = len(prefix) + len(data)
            return bytes.__new__(cls, (4 - length % 4) % 4)

        def buffers(self):
            return [self]

        def get_bytes(self):
            return self

    param_types = string_c(_prefix, _data, _padding)

    @classmethod
    def _make(cls, data):
        pfx = cls._prefix.new(data)
        data = cls._data.new(data)
        padding = cls._padding.new(pfx, data)

        return tuple.__new__(cls, (pfx, data, padding))


class vector_c(namedtuple('vector_c', 't num items'), BareType):

    number = int_c(0x1cb5c415)

    _vector_types = {}

    def __new__(cls, *args, **kwargs):
        if cls is vector_c:
            return cls._type_factory(cls, *args, **kwargs)
        return cls._make(*args, **kwargs)

    @staticmethod
    def _type_factory(cls, item_type):
        key = (cls, item_type,)
        vector_cls = cls._vector_types.get(key)
        if vector_cls is None:
            name = '{}_{}'.format(cls.__name__, item_type.__name__)
            vector_c._vector_types[key] = type(name, (cls,), {'_make': partial(cls._make, item_type)})
            vector_cls = vector_c._vector_types.get(key)
        return vector_cls

    @classmethod
    def _make(cls, t, iterable):
        items = [t(i) for i in iterable]
        return super()._make((t, int_c(len(items)), items,))

    def buffers(self):
        bufs = int_c.buffers(len(self.items))
        for item in self.items:
            bufs.extend(item.buffers())
        return bufs


class bytes_c(string_c):
    pass


class Vector(BoxedType, vector_c):

    def __new__(cls, *args, **kwargs):
        if cls is Vector:
            return vector_c._type_factory(cls, *args, **kwargs)
        return vector_c.__new__(cls, *args, **kwargs)
