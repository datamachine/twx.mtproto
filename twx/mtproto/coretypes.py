from collections import namedtuple
from collections import UserList
from struct import Struct
from functools import partial, partialmethod
from io import BytesIO

try:
    from . util import crc32
except SystemError:
    from util import crc32

class MTProtoException(Exception):
    pass

class MTProtoKeyNotReadyError(MTProtoException):
    pass

class MTProtoStreamReadError(MTProtoException):
    pass

class MTProtoInvalidNumberError(MTProtoException):
    pass

class MTProtoCRCMismatchError(MTProtoException):
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
    _combinators = {}

    __slots__ = ()

    def __new__(cls, name):
        if cls is MTPType:
            return type(name, (MTPType,), dict(_type_constructors={}))
        raise NotImplementedError()

    @staticmethod
    def add_combinator(number, bare_type):
        return MTPType._combinators.setdefault(number, bare_type)

    @staticmethod
    def get_combinator(number):
        return MTPType._combinators.get(number, NotImplemented)

    @classmethod
    def from_bytes(cls, data):
        if cls is MTPType:
            stream = BytesIO(data)

            number = int.from_bytes(stream.read(4), 'little')
            combinator = cls.get_combinator(number)
            return combinator.from_stream(stream)
        raise NotImplementedError()


class BareType:

    def __new__(cls, *args, **kwargs):
        if cls is BareType:
            return cls._bare_type_factory(*args, **kwargs)

        return cls.new(*args, **kwargs)

    @classmethod
    def _bare_type_factory(cls, name, number, params, param_types, result_type):
        param_tuple = namedtuple(name, params)
        param_types = param_tuple(*param_types)

        attrs = dict(
            number=int_c(number),
            param_types=param_types,
            )

        bare_type = type(name, (cls, param_tuple, result_type,), attrs)
        return MTPType.add_combinator(bare_type.number, bare_type)
        
    @classmethod
    def new(cls, *args, **kwargs):
        
        len_args = len(args)
        result_args = []
        i = 0
        for param, param_type in cls.param_types._asdict().items():
            value = args[i] if i < len_args else kwargs[param]
            result_args.append(param_type(value))
            i += 1

        return cls._make(result_args)

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

    @classmethod
    def from_stream(cls, stream):
        items = []

        for param_type in cls.param_types._asdict().values():
            items.append(param_type.from_stream(stream))
        return tuple.__new__(cls, items)

class BoxedType:

    _base_boxed_types = {}
    _boxed_types = {}

    def __new__(cls, *args, **kwargs):
        if cls is BoxedType:
            return cls._get_base_boxed_type(*args, **kwargs)

        boxed_type = cls._get_boxed_type(*args, **kwargs)
        return boxed_type.new(*args, **kwargs)

    @classmethod
    def new(cls, iterable):
        return tuple.__new__(cls, iterable)

    @classmethod
    def _boxed_base_type_factory(cls, name, base_type):
        attrs = dict(
            name=name
            )
        return type(name, (cls, base_type,), attrs)

    @classmethod
    def _get_base_boxed_type(cls, name, base_type):
        base_boxed_type = cls._base_boxed_types.get(name)
        if base_boxed_type is None:
            base_boxed_type = cls._base_boxed_types.setdefault(name, cls._boxed_base_type_factory(name, base_type))
        return base_boxed_type

    @classmethod
    def _get_boxed_type(cls, obj):
        bare_type = type(obj)
        boxed_type = cls._boxed_types.get(bare_type)
        if boxed_type is None:
            boxed_type = cls._boxed_types.setdefault(bare_type, cls._boxed_type_factory(bare_type))
        return boxed_type

    @classmethod
    def _boxed_type_factory(cls, bare_type):
        return type(cls.name, (cls, bare_type,), dict())

    def buffers(self):
        return self.number.buffers() + super().buffers()    


class Function(BareType):

    def __new__(cls, *args, **kwargs):
        if cls is Function:
            return cls._bare_type_factory(*args, **kwargs)
        return cls.new(*args, **kwargs)

    def buffers(self):
        return self.number.buffers() + super().buffers()

class _IntMixin:
    __slots__ = ()


    def buffers(self):
        return [self.get_bytes()]

    def get_bytes(self):
        return self.to_bytes(self._num_bytes, 'little')

    @classmethod
    def from_stream(cls, stream):
        return cls(int.from_bytes(stream.read(cls._num_bytes), 'little'))

class int_c(int, _IntMixin):

    """
    int ? = Int
    """
    __slots__ = ()

    number = 'int ? = Int'

    _num_bytes = 4


int_c.number = generate_number(int_c.number)

int32_c = int_c  # alias for general utility


class long_c(int, _IntMixin):

    __slots__ = ()

    number = generate_number('long ? = Long')

    _num_bytes = 8

int64_c = long_c  # alias for general utility


class int128_c(int, _IntMixin):

    number = generate_number('int 4*[ int ] = Int128')

    _num_bytes = 16


class int256_c(int, _IntMixin):

    number = generate_number('int 8*[ int ] = Int256')

    _num_bytes = 32


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
    def new(cls, data):
        pfx = cls._prefix.new(data)
        data = cls._data.new(data)
        padding = cls._padding.new(pfx, data)

        return tuple.__new__(cls, (pfx, data, padding))

    @classmethod
    def from_stream(cls, stream):
        length = stream.read(1)[0]
        count = 1
        if length == 254:
            length = int.from_bytes(stream.read(3), 'little')
            count += 3
        data = stream.read(length)
        count += length

        # clear the padding from the stream
        stream.read((4 - count % 4) % 4)

        return cls.new(data)


class vector_c(namedtuple('vector_c', 't num items'), BareType):

    number = int_c(0x1cb5c415)

    _vector_types = {}

    def __new__(cls, *args, **kwargs):
        if cls is vector_c:
            return cls.get_vector_type(*args, **kwargs)
        return cls.new(*args, **kwargs)

    @classmethod
    def new(cls, items):
        items = tuple(map(cls._item_type, items))
        return tuple.__new__(cls, (cls._item_type, len(items), items,))

    @classmethod
    def get_vector_type(cls, item_type):
        key = (cls.__name__, item_type.__name__,)
        
        result = cls._vector_types.get(key)
        if result is None:
            result = cls._vector_types.setdefault(key, vector_c._type_factory(cls, item_type))

        return result

    @staticmethod
    def _type_factory(cls, item_type):
        attrs = dict(
            _item_type=item_type
            )

        return type(cls.__name__, (cls,), attrs)

    def buffers(self):
        bufs = int_c.buffers(len(self.items))
        for item in self.items:
            bufs.extend(item.buffers())
        return bufs

    @classmethod
    def from_stream(cls, stream):
        num = int_c.from_stream(stream)
        items = []
        for i in iter(range(num)):
            items.append(cls._item_type.from_stream(stream))
        return cls.new(items)

class bytes_c(string_c):
    pass


class Vector(vector_c, BoxedType):
        
    def __new__(cls, *args, **kwargs):
        if cls is Vector:
            return cls.get_vector_type(*args, **kwargs)
        return cls.new(*args, **kwargs)

    @classmethod
    def from_stream(cls, stream):
        number = int_c.from_stream(stream)
        if number != cls.number:
            raise MTProtoInvalidNumberError()
        return super().from_stream(stream)
