#!/usr/bin/env python3

from __future__ import print_function

import sys
import os
import io

sys.path.insert(0, os.getcwd())

import argparse
from twx.mtproto import mtproto
from twx.mtproto.tl import *
from twx.mtproto.util import to_hex

from configparser import ConfigParser


parser = argparse.ArgumentParser()
parser.add_argument('--config', type=argparse.FileType(), default='mtproto.conf')
args = parser.parse_args()

config = ConfigParser()
config.read_file(args.config)

mtproto = mtproto.MTProtoClient(config)
mtproto.init_connection()
