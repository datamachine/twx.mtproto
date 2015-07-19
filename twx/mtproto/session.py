if __name__ == '__main__':
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path('../..').resolve()))

import random

from collections import namedtuple

from twx.mtproto.connection import MTProtoConnection
from twx.mtproto import tl

__all__ = ('MTProtoSession',)

class MTProtoSession(namedtuple('MTProtoSession', 'id')):

    def __new__(cls, id):
        return super().__new__(cls, tl.int64_c(id))

    @classmethod
    def new(cls):
        return cls(random.SystemRandom().getrandbits(64))


if __name__ == '__main__':
    session = MTProtoSession(10)
    print(session, session.to_bytes())
