from ipaddress import ip_address
from collections import namedtuple

class BuiltinDC(namedtuple('BuiltinDC', 'id address port')):

    def __new__(cls, id, address, port):
        return tuple.__new__(cls, (int(id), ip_address(address), int(port),))

class MTProtoDC:
    _builtin_dcs = [
        BuiltinDC(1, '149.154.175.50', 443),
        BuiltinDC(2, '149.154.167.51', 443),
        BuiltinDC(3, '149.154.175.100', 443),
        BuiltinDC(4, '149.154.167.91', 443),
        BuiltinDC(5, '149.154.171.5', 443),
    ]

    _builtInDcsIPv6 = [
        BuiltinDC(1, '2001:b28:f23d:f001::a', 443),
        BuiltinDC(2, '2001:67c:4e8:f002::a', 443),
        BuiltinDC(3, '2001:b28:f23d:f003::a', 443),
        BuiltinDC(4, '2001:67c:4e8:f004::a', 443),
        BuiltinDC(5, '2001:b28:f23f:f005::a', 443),
    ]

    _builtInTestDcs = [
        BuiltinDC(1, '149.154.175.10', 443),
        BuiltinDC(2, '149.154.167.40', 443),
        BuiltinDC(3, '149.154.175.117', 443),
    ]

    _builtInTestDcsIPv6 = [
        BuiltinDC(1, '2001:b28:f23d:f001::e', 443),
        BuiltinDC(2, '2001:67c:4e8:f002::e', 443),
        BuiltinDC(3, '2001:b28:f23d:f003::e', 443),
    ]

if __name__ == '__main__':
    dc = MTProtoDC()
