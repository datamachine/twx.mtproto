from enum import Enum
import asyncio

class MTProtoConnection:

    class ConnectionType(str, Enum):
        TCP = 'TCP'

    TCP = ConnectionType.TCP

    def __new__(cls, connection_type):
        connection_type = cls.ConnectionType(connection_type)
        if connection_type is cls.ConnectionType.TCP:
            return MTProtoTCPConnection.__new__(MTProtoTCPConnection)


class MTProtoTCPConnection:
    pass


if __name__ == '__main__':
    con = MTProtoConnection('TCP')

    print(con, ...)
