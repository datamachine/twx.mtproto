import logging
import asyncio
import random

from ipaddress import ip_address
from collections import namedtuple
from urllib.parse import urlsplit

from . import prime

log = logging.getLogger(__package__)

print(__package__)

try:
    from . import scheme
    from .protocols import MTProtoClientProtocol, ConnectionType
except SystemError:
    import scheme
    from protocols import MTProtoClientProtocol

log = logging.getLogger(__name__)

class DCInfo(namedtuple('DCInfo', 'address port connection_type')):

    def __new__(cls, address, port, connection_type):
        return super().__new__(cls, ip_address(address), int(port), ConnectionType(connection_type))

    @classmethod
    def new(cls, url):
        url = urlsplit(url)
        return cls(url.hostname, url.port, url.scheme.upper())

class DataCenter:

    def __init__(self, url):
        self.dc = DCInfo.new(url)
        self.connection = None
        self.last_msg_id = 0
        self.auth_key = None
        self.random = random.SystemRandom()

    def init(self, loop):
        pass
        # self.conn = MTProtoConnection.new(self.dc_info.connection_type)
        # self.conn_coro = loop.create_connection(lambda: self.conn, str(self.dc_info.address), self.dc_info.port)

        # f1 = asyncio.async(self.conn_coro)
        # asyncio.async(self.run(loop))
        # f1.add_done_callback(lambda x: self.create_auth_key())
        # loop.run_until_complete(asyncio.wait(tasks))

    @asyncio.coroutine
    def send_insecure_message(self, request):
        yield from self.connection.send_insecure_message(self.generate_message_id(), request)

    @asyncio.coroutine
    def create_auth_key(self):
        from random import SystemRandom
        rand = SystemRandom()

        req_pq = scheme.req_pq(nonce=rand.getrandbits(128))
        log.debug(req_pq)
        yield from self.connection.send_insecure_message(req_pq)
        response = yield from self.connection.get_ingress()
        resPQ = response.get_message()
        log.debug(resPQ)

        pq = int.from_bytes(resPQ.pq.data, 'big')

        p, q = prime.primefactors(pq, True)

    @asyncio.coroutine
    def async_run(self, loop):
        self.connection = MTProtoClientProtocol.new('TCP')
        coro = self.connection.create_connection('149.154.167.40', 443, loop=loop)

        asyncio.async(self.connection.handle_egress(), loop=loop)
        asyncio.async(coro, loop=loop)
        asyncio.async(self.create_auth_key(), loop=loop)

if __name__ == '__main__':
    import sys

    log.setLevel(logging.DEBUG)
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG)
    log.addHandler(ch)

    dc = DataCenter('tcp://149.154.167.40:443')

    loop = asyncio.get_event_loop()
    asyncio.async(dc.async_run(loop), loop=loop)
    loop.run_forever()
    loop.close()
