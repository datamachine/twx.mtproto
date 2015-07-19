import logging

from ipaddress import ip_address
from collections import namedtuple
from urllib.parse import urlsplit

from . connection import MTProtoConnection

log = logging.getLogger(__name__)

class DCInfo(namedtuple('DCInfo', 'address port connection_type')):

    def __new__(cls, address, port, connection_type):
        return super().__new__(cls, ip_address(address), int(port), MTProtoConnection.ConnectionType(connection_type))

    @classmethod
    def new(cls, url):
        url = urlsplit(url)
        return cls(url.hostname, url.port, url.scheme.upper())


class DataCenter:

    def __init__(self, url):
        self.dc_info = DCInfo.new(url)
        self.connections = []

    def establish_connection(self):
        connection = MTProtoConnection(self.dc_info.connection_type)
        print('test', ...)
        log.debug('connection')
