import random
import logging

from . import scheme

__all__ = ('MTProtoSessionData',)

log = logging.getLogger(__package__)


class MTProtoSessionData:

    def __init__(self, id):
        if id is None:
            id = random.SystemRandom().getrandbits(64)
            log.debug('no session_id provided, generated new session_id: {}'.format(id))

        self._id = scheme.int64_c(id)
        self._auth_keys = dict()
