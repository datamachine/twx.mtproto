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
from functools import partial
from io import StringIO, StringIO
from datetime import datetime


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

def reset_stdio():
    set_stdio(None, None)

class _Stdio:

    def __init__(self, output_win, *attrs):
        self.output_win = output_win
        self.attrs = attrs

    def write(self, string):
        if string != '\n':
            string = '{}: {}'.format(datetime.now().strftime('%X.%f'), string)
        self.output_win.addstr(string, *self.attrs)
        self.flush()

    def flush(self):
        self.output_win.refresh()

class CLIApp:

    def __init__(self):
        self.config = None
        self.client = None
        self.arg_parser = argparse.ArgumentParser(prog='')
        self._init_commands()

    def create_client(config):
        self.config = config
        self.client = mtproto.MTProtoClient(config)

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
        if self.client is not None:
            self.client.init_connection()
        else:
            print('MTProto client has not yet been created', file=sys.stderr)

    def cmd_quit(self):
        self.loop.stop()

    def process_input(self, string):
        cmd = shlex.split(string)
        try:
            args = self.arg_parser.parse_args(cmd)
        except SystemExit:
            return

        func = args.func
        kwargs = dict(args._get_kwargs())
        del kwargs['func']

        func(**kwargs)


class CursesCLI(CLIApp):

    def __init__(self):
        super().__init__()
        self.stdscr = None

    @asyncio.coroutine
    def _curses_refresh(self):

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
        cmd_win.move(0,0)

        curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_RED)

        stdout = _Stdio(output_win)
        stderr = _Stdio(output_win, curses.color_pair(1))

        set_stdio(stdout, stderr)

        parser = argparse.ArgumentParser()
        parser.add_argument('--config', type=argparse.FileType(), default='mtproto.conf')
        args = parser.parse_args()

        config = ConfigParser()
        config.read_file(args.config)

        buf = StringIO()
        cmd_curs = [0, 0]
        while True:
            try:
                key = cmd_win.getkey()
                if key == '\n':
                    buf.seek(0)
                    text = buf.read()
                    if text.strip():
                        output_win.addstr('\ncmd: {}\n'.format(text))
                        output_win.refresh()
                    buf.seek(0)
                    string = buf.read()
                    buf.truncate(0)

                    self.process_input(string)

                    cmd_win.clear()
                elif key == '\x7f':
                    pos = buf.tell()
                    buf.truncate(pos-1)
                elif key == '\x15':
                    string = buf.read()
                    buf.truncate(0)
                    buf.write(string)
                elif key.isprintable():
                    buf.write(key)
                else:
                    print('unhandled key \'{}\''.format(repr(key)))

                pos = buf.tell()
                buf.seek(0)
                cmd_line = buf.read()
                cmd_win.clear()
                cmd_win.addstr(cmd_line)
                cmd_win.move(0, len(cmd_line))

                cmd_win.refresh()
                output_win.refresh()
            except Exception as e:
                print(e)
            except KeyboardInterrupt as e:
                reset_stdio()
                sys.exit()

    def _wrapped_run(self, stdscr):
        self.stdscr = stdscr

        loop = asyncio.get_event_loop()
        loop.run_until_complete(self._curses_refresh())
        loop.close()

    def run(self):
        locale.setlocale(locale.LC_ALL, '')

        curses.wrapper(self._wrapped_run)

def main():
    cli = CursesCLI()
    cli.run()

if __name__ == "__main__":
    main()
