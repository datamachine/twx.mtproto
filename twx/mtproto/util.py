from codecs import encode

import logging
import zlib

logging.basicConfig(filename='debug.log', level=logging.DEBUG)

def to_hex(_bytes, width=4):
    if len(_bytes) == 0:
        return None
    string = ""
    bytes_iter = iter(_bytes)
    try:
        if width < 1:
            while True:
                val = next(bytes_iter)
                string += '{:02X}'.format(val)

        while True:
            for i in iter(range(width)):
                string += '{:02X}'.format(next(bytes_iter))
            string += " "
    except StopIteration:
        return string

def print_hex(_bytes, width=4):
    print(to_hex(_bytes, width))


def crc32(data):
    return zlib.crc32(data) & 0xffffffff  # crc32 might be more than 32 bits because: CPython
