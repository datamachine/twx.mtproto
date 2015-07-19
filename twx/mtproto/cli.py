#!/usr/bin/env python

from __future__ import print_function

import logging

import sys
import os
import io

sys.path.insert(0, os.getcwd())

import argparse

from configparser import ConfigParser

import asyncio
import shlex

from enum import Enum
import locale
import curses
from functools import partial
from io import StringIO, StringIO
from datetime import datetime

import atexit

from collections import OrderedDict

from twx.mtproto import mtproto
from twx.mtproto.tl import *
from twx.mtproto.util import to_hex

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

@atexit.register
def reset_stdio():
    set_stdio(None, None)


class WindowLogHandler(logging.Handler):

    def __init__(self, window):
        logging.Handler.__init__(self)
        self.window = window

    def emit(self, record):
        self.window.addstr('\n{}'.format(record.getMessage()))

class StdioWrapper(logging.Handler):

    def __init__(self, window, *attrs):
        self.window = window
        self.attrs = attrs

    def write(self, string):
        fmt = '\n{}'
        if not string.strip():
            fmt = '{}'

        self.window.addstr(fmt.format(string), *self.attrs)

    def flush(self):
        pass
        # self.window.refresh()

class Point2D(namedtuple('Point2D', 'x y')):

    def __new__(cls, x, y=None):
        if y is None:
            iterable = x
            return tuple.__new__(cls, iterable)
        else:
            return super().__new__(cls, x, y)


class Size2D(namedtuple('Size2D', 'width height')):

    def __new__(cls, width, height=None):
        if height is None:
            iterable = width
            return tuple.__new__(cls, iterable)
        else:
            return super().__new__(cls, width, height)


class Rect2D(namedtuple('Rect2D', 'loc size')):

    def __new__(cls, loc, size=None):
        if size is None:
            iterable = loc
            return tuple.__new__(cls, iterable)
        else:
            return super().__new__(cls, loc, size)


class Position(str, Enum):
    ABSOLUTE = 'absolute'
    RELATIVE = 'relative'


class ReferenceBorder(str, Enum):
    TOP = 'top'
    BOTTOM = 'bottom'
    LEFT = 'left'
    RIGHT = 'right'


class Window:

    def __init__(self, parent, rect, position=Position.ABSOLUTE, ref=ReferenceBorder.TOP):
        self.parent = parent
        self.rect = Rect2D(rect)
        self.position = Position(position)
        self.ref = ReferenceBorder(ref)


class CursesCLI:

    _InputMode = Enum('InputMode', 'COMMAND_MODE EVAL_MODE')

    COMMAND_MODE = _InputMode.COMMAND_MODE
    EVAL_MODE = _InputMode.EVAL_MODE

    def __init__(self):
        self.done = False

        self.windows = OrderedDict()

        self.command_history = []
        self.command_history_idx = 0
        self.command_history_buf = []
        self.config = None
        self.client = None
        self.exit_code = 0
        self.ps1_text = 'twx.mtproto$'
        self.cmd_parser = argparse.ArgumentParser(prog='$')
        self._init_commands()
        self.mode = CursesCLI.COMMAND_MODE

    def create_client(self, config):
        self.config = config
        self.client = mtproto.MTProtoClient(config)

    def _init_commands(self):
        self.cmd_parser.set_defaults(func=lambda: None)
        subparsers = self.cmd_parser.add_subparsers(title='commands', prog='cmd', metavar='', help='')

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

        # quit
        eval_mode = subparsers.add_parser('eval', aliases=['#'], help='switch to eval mode')
        eval_mode.set_defaults(func=self.cmd_switch_to_eval_mode)

    def cmd_echo(self, text, count):
        for i in iter(range(count)):
            print(i, text)

    def cmd_init(self):
        if self.client is not None:
            self.client.init()
        else:
            print('MTProto client has not yet been created', file=sys.stderr)

    def cmd_quit(self):
        print('exiting...', file=sys.stderr)
        self.done = True

    def cmd_switch_to_eval_mode(self):
        self.mode = CursesCLI.EVAL_MODE
        self.ps1_text = 'twx.mtproto#'
        ps1_win.clear()
        ps1_win.addstr(self.ps1_text)
        print("Now in eval mode. Enter '$' to return to command mode")

    def cmd_switch_to_command_mode(self):
        self.mode = CursesCLI.COMMAND_MODE
        self.ps1_text = 'twx.mtproto$'
        ps1_win.clear()
        ps1_win.addstr(self.ps1_text)
        print("Now in command mode. Enter '-h' for help")

    def process_cmd_input(self, string):
        cmd = shlex.split(string)
        try:
            args = self.cmd_parser.parse_args(cmd)
        except SystemExit:
            return

        func = args.func
        kwargs = dict(args._get_kwargs())
        del kwargs['func']

        func(**kwargs)

    def process_eval_input(self, string):
        if string.strip() == '$':
            self.cmd_switch_to_command_mode()
        else:
            _locals = dict(self=self)
            print(eval(string, {}, _locals))

    def process_input(self, string):
        if self.mode == CursesCLI.COMMAND_MODE:
            self.process_cmd_input(string)
        elif self.mode == CursesCLI.EVAL_MODE:
            self.process_eval_input(string)

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
        stdscr = self.windows['stdscr']
        height, width = stdscr.getmaxyx()

        self.windows['root'] = stdscr.subwin(height, width, 0, 0)
        root_win = self.windows['root']

        self.windows['output'] = root_win.subwin(height-2, width, 0, 0)
        output_win = self.windows['output']

        output_win.idlok(1)
        output_win.scrollok(1)

        y, x = output_win.getmaxyx()
        output_win.move(y-1, 0)

        curses.init_pair(1, curses.COLOR_RED, curses.COLOR_BLACK)
        curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)

        stderr_wrapper = StdioWrapper(output_win, curses.color_pair(1))
        stdout_wrapper = StdioWrapper(output_win, curses.color_pair(2))

        set_stdio(stdout_wrapper, stderr_wrapper)

        cy, cx = output_win.getmaxyx()
        self.windows['separator'] = root_win.derwin(1, cx, cy, 0)
        separator_win = self.windows['separator']
        separator_win.hline(0, 0, '-', x)

        self.windows['ps1'] = root_win.derwin(1, len(self.ps1_text)+1, height-1, 0)
        ps1_win = self.windows['ps1']
        ps1_win.addstr(self.ps1_text)

        cy, cx = ps1_win.getmaxyx()
        self.windows['commands'] = root_win.derwin(1, width - cx, height-1, cx)
        cmd_win = self.windows['commands']
        cmd_win.move(0, 0)
        cmd_win.keypad(1)

        parser = argparse.ArgumentParser()
        parser.add_argument('--config', type=argparse.FileType(), default='mtproto.conf')
        args = parser.parse_args()

        config = ConfigParser()
        config.read_file(args.config)
        
        self.create_client(config)

        buf = list()

        window_handler = WindowLogHandler(output_win)
        window_handler.setLevel(logging.DEBUG)

        logger = logging.getLogger('output_win')
        logger.addHandler(window_handler)
        logger.setLevel(logging.DEBUG)

        for name, win in self.windows.items():
            win.noutrefresh()
        curses.doupdate()

        while not self.done:
            try:
                key = cmd_win.getkey()
                if key == '\n':
                    string = ''.join(buf).strip()

                    if string.strip():
                        self.add_cmd_history(buf)
                        logger.info(string)
                        logger.info(curses.__file__)
                    else:
                        output_win.addstr('\n')

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
                    if cx < len(buf):
                        cmd_win.move(cy, cx+1)
                elif key == 'KEY_UP':
                    buf = self.prev_cmd_history(buf)
                    cmd_win.move(0, len(buf))
                elif key == 'KEY_DOWN':
                    buf = self.next_cmd_history(buf)
                    cmd_win.move(0, len(buf))
                elif key == 'KEY_RESIZE':
                    # TODO: resize
                    ...
                elif len(key) == 1 and key.isprintable():
                    cy, cx = cmd_win.getyx()
                    if 0 <= cx < 255 and len(buf) < 255:
                        buf.insert(cx, key)
                        cmd_win.move(cy, cx+1)
                else:
                    logger.debug('unhandled key: \'{}\''.format(repr(key)))

                cy, cx = cmd_win.getyx()
                cmd_win.clear()

                cmd_win.addstr(''.join(buf))
                cmd_win.move(cy, cx)

                for name, win in self.windows.items():
                    win.noutrefresh()
                curses.doupdate()
            except Exception as e:
                logger.critical(e)
            except KeyboardInterrupt as e:
                return 130

    def _wrapped_run(self, stdscr):
        self.windows['stdscr'] = stdscr

        loop = asyncio.get_event_loop()
        self.exit_code = loop.run_until_complete(self._curses_refresh())
        loop.close()

    def run(self):
        locale.setlocale(locale.LC_ALL, '')
        curses.wrapper(self._wrapped_run)
        return self.exit_code

def main():
    cli = CursesCLI()
    code = cli.run()
    reset_stdio()
    sys.exit(code)

if __name__ == "__main__":

    main()
