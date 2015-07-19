#!/usr/bin/env python

import sys
import os
import runpy

sys.path.insert(0, os.getcwd())

from twx.mtproto.cli import main

if __name__ == "__main__":
    sys.exit(main())
