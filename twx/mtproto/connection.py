from enum import Enum

class ConnectionType(str, Enum):
    TCP = 'TCP'

class MTProtoConnection:
    def __new__(cls, connection_type):
        connection_type = ConnectionType(connection_type)
        if connection_type is ConnectionType.TCP:
            return MTProtoTCPConnection.__new__(MTProtoTCPConnection)

class MTProtoTCPConnection:
    pass

if __name__ == '__main__':
    con = MTProtoConnection('TCP')

    print(con, ...)
