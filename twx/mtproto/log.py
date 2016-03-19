import logging
import sys

log = logging.getLogger(__package__)
log.setLevel(logging.DEBUG)
stdout_stream_handler = logging.StreamHandler(sys.stdout)
stdout_stream_handler.setLevel(logging.DEBUG)
log.addHandler(stdout_stream_handler)
