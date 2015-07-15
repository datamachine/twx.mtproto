#!/usr/bin/env python

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

import asyncio
import shlex

import locale
import curses
from io import StringIO, StringIO

locale.setlocale(locale.LC_ALL, '')
code = locale.getpreferredencoding()

def save_stdio_state(func):
    sys_stdout = sys.stdout
    sys_stderr = sys.stderr

    def wrapper(stdout, stderr):
        if stdout is None:
            stdout = sys_stdout
        if stderr is None:
            stderr = sys_stderr
        return func(stdout, stderr)

    return wrapper

@save_stdio_state
def set_stdio(stdout, stderr):
    sys.stdout = stdout
    sys.stderr = stderr

class _Stdio:

    def __init__(self, output_win):
        self.output_win = output_win

    def write(self, string):
        if string == '\n':
            return
        self.output_win.addstr('\n')
        self.output_win.addstr(string)
        self.flush()

    def flush(self):
        self.output_win.refresh()

class CLI:

    def __init__(self, config):
        self.config = config
        self.client = mtproto.MTProtoClient(config)
        self.loop = asyncio.get_event_loop()
        self.arg_parser = argparse.ArgumentParser(prog='')
        self._init_commands()

        self.stdscr = None  # for curses

    def _init_commands(self):
        subparsers = self.arg_parser.add_subparsers(title='commands', prog='', metavar='', help='')

        # echo
        echo = subparsers.add_parser('echo')
        echo.add_argument('text')
        echo.add_argument('--count', type=int, default=1)
        echo.set_defaults(func=self.cmd_echo)

        # init
        init = subparsers.add_parser('init', help='Initialize the MTProto session', description='Initializet the MTProto session')
        init.set_defaults(func=self.cmd_init)

        # quit
        quit = subparsers.add_parser('quit', aliases=['exit'], help='Quit the program')
        quit.set_defaults(func=self.cmd_quit)

    def cmd_echo(self, text, count):
        for i in iter(range(count)):
            print(i, text)

    def cmd_init(self):
        self.client.init_connection()

    def cmd_quit(self):
        self.loop.stop()

    def process_input(self):
        cmd = shlex.split(self.io_read.readline())
        try:
            args = self.arg_parser.parse_args(cmd)
        except SystemExit:
            return

        func = args.func
        kwargs = dict(args._get_kwargs())
        del kwargs['func']

        try:
            func(**kwargs)
        except Exception as e:
            print(e, file=sys.stderr)

    @asyncio.coroutine
    def _curses_refresh(self):
        from curses.textpad import Textbox
        try:
            height, width = self.stdscr.getmaxyx()

            output_win = self.stdscr.subwin(height-2, width, 0, 0)

            output_win.idlok(1)
            output_win.scrollok(1)

            y, x = output_win.getmaxyx()
            output_win.move(y-1, 0)

            separator_win = self.stdscr.subwin(1, x, y, 0)
            separator_win.hline(0, 0, '-', x)
            separator_win.refresh()
            
            ps1_text = 'twx.mtproto: '
            ps1_win = self.stdscr.subwin(1, len(ps1_text)+1, height-1, 0)
            ps1_win.addstr(ps1_text)
            ps1_win.refresh()

            cmd_win = self.stdscr.subwin(1, width - len(ps1_text)-1, height-1, len(ps1_text))

            buf = StringIO()

            while True:
                key = cmd_win.getkey()
                if key == '\n':
                    buf.seek(0)
                    text = buf.read()
                    if text.strip():
                        output_win.addstr('\n')
                        output_win.addstr(text)
                        output_win.refresh()
                    buf.seek(0)
                    buf.truncate()
                    cmd_win.clear()
                elif key.isprintable():
                    buf.write(key)
                else:
                    output_win.addstr('\n')
                    output_win.addstr(repr(key))
                buf.seek(0)
                cmd_win.clear()
                cmd_win.addstr(buf.read())
                cmd_win.refresh()
                output_win.refresh()
        except Exception as e:
            self.cmd_quit()

    def run_curses(self, stdscr):
        self.stdscr = stdscr

        r, w = os.pipe()
        with os.fdopen(r) as r, os.fdopen(w) as w:
            self.loop.run_until_complete(self._curses_refresh())
            self.loop.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', type=argparse.FileType(), default='mtproto.conf')
    args = parser.parse_args()

    config = ConfigParser()
    config.read_file(args.config)

    cli = CLI(config)

    curses.wrapper(cli.run_curses)

if __name__ == "__main__":
    main()
