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

    def write(self, string, ts=False):
        if ts:
            string = '{}: {}'.format(datetime.now().strftime('%X.%f'), string)
        self.output_win.addstr(string, *self.attrs)
        self.flush()

    def flush(self):
        self.output_win.refresh()

class CLIApp:

    def __init__(self):
        self.config = None
        self.client = None
        self.exit_code = 0
        self.ps1_text = 'twx.mtproto# '
        self.arg_parser = argparse.ArgumentParser(prog='')
        self._init_commands()

    def create_client(self, config):
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
        self.root_win = None
        self.command_history = []
        self.command_history_idx = 0
        self.command_history_buf = []

    def add_cmd_history(self, buf):
        if 0 <= self.command_history_idx < len(self.command_history):
            if buf == self.command_history[self.command_history_idx]:
                self.command_history_idx = len(self.command_history)
                return

        self.command_history.append(buf)
        self.command_history_idx = len(self.command_history)

    def prev_cmd_history(self, buf):
        if len(self.command_history) <= self.command_history_idx:
            self.command_history_buf = buf
            self.command_history_idx = len(self.command_history)

        self.command_history_idx -= 1
        if self.command_history_idx < 0:
            self.command_history_idx = 0
        return list(self.command_history[self.command_history_idx])

    def next_cmd_history(self, buf):
        self.command_history_idx += 1
        if self.command_history_idx == len(self.command_history):
            result = self.command_history_buf
            self.command_history_buf = []
            return result

        if self.command_history_idx > len(self.command_history):
            self.command_history_idx = len(self.command_history)
            return buf

        if 0 <= self.command_history_idx < len(self.command_history):
            return list(self.command_history[self.command_history_idx])

        return []

    @asyncio.coroutine
    def _curses_refresh(self):
        height, width = self.stdscr.getmaxyx()

        self.root_win = self.stdscr.subwin(height, width, 0, 0)

        output_win = self.root_win.subwin(height-2, width, 0, 0)

        output_win.idlok(1)
        output_win.scrollok(1)

        y, x = output_win.getmaxyx()
        output_win.move(y-1, 0)

        separator_win = self.root_win.subwin(1, x, y, 0)
        separator_win.hline(0, 0, '-', x)
        separator_win.refresh()
        
        ps1_text = self.ps1_text
        ps1_win = self.root_win.subwin(1, len(ps1_text)+1, height-1, 0)
        ps1_win.addstr(ps1_text)
        ps1_win.refresh()

        cmd_win = self.root_win.subwin(1, width - len(ps1_text)-1, height-1, len(ps1_text))
        cmd_win.move(0,0)
        cmd_win.keypad(1)

        curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_RED)

        stdout = _Stdio(output_win)
        stderr = _Stdio(output_win, curses.color_pair(1))

        set_stdio(stdout, stderr)

        parser = argparse.ArgumentParser()
        parser.add_argument('--config', type=argparse.FileType(), default='mtproto.conf')
        args = parser.parse_args()

        config = ConfigParser()
        config.read_file(args.config)
        
        self.create_client(config)

        buf = list()


        while True:
            try:
                key = cmd_win.getkey()
                if key == '\n':
                    string = ''.join(buf).strip()
                    
                    if string.strip():
                        self.add_cmd_history(buf)
                        print(self.command_history)

                        output_win.addstr('{}\n'.format(string))
                        output_win.refresh()
                    else:
                        output_win.addstr('\n')
                        output_win.refresh()

                    buf = list()
                    cmd_win.clear()
                    self.process_input(string)
                elif key == '\x7f':
                    cy, cx = cmd_win.getyx()
                    if 0 < cx <= len(buf):
                        del buf[cx-1]
                        cmd_win.move(cy, cx-1)
                elif key == '\x15':
                    cy, cx = cmd_win.getyx()
                    if 0 < cx:
                        if cx < len(buf):
                            del buf[0:cx]
                        else:
                            buf = list()
                        cmd_win.move(0, 0)
                elif key == 'KEY_LEFT':
                    cy, cx = cmd_win.getyx()
                    if 0 < cx:
                        cmd_win.move(cy, cx-1)
                elif key == 'KEY_RIGHT':
                    cy, cx = cmd_win.getyx()
                    if cx < 255:
                        cmd_win.move(cy, cx+1)
                elif key == 'KEY_UP':
                    buf = self.prev_cmd_history(buf)
                elif key == 'KEY_DOWN':
                    buf = self.next_cmd_history(buf)
                elif key == 'KEY_RESIZE':
                    ...
                    # TODO: resize
                    # self.do_resize(output_win, separator_win, ps1_win, cmd_win)
                elif len(key) == 1 and key.isprintable():
                    cy, cx = cmd_win.getyx()
                    if 0 <= cx < 255 and len(buf) < 255:
                        buf.insert(cx, key)
                        cmd_win.move(cy, cx+1)
                else:
                    print('unhandled key: \'{}\''.format(repr(key)))

                cy, cx = cmd_win.getyx()
                cmd_win.clear()
                cmd_win.refresh()

                cmd_win.addstr(''.join(buf))
                cmd_win.move(cy, cx)
                output_win.refresh()
                cmd_win.refresh()
            except Exception as e:
                print(e)
            except KeyboardInterrupt as e:
                reset_stdio()
                return 130

    def _wrapped_run(self, stdscr):
        self.stdscr = stdscr

        loop = asyncio.get_event_loop()
        self.exit_code = loop.run_until_complete(self._curses_refresh())
        loop.close()

    def run(self):
        locale.setlocale(locale.LC_ALL, '')
        curses.wrapper(self._wrapped_run)
        sys.exit(self.exit_code)

def main():
    cli = CursesCLI()
    cli.run()

if __name__ == "__main__":
    main()
