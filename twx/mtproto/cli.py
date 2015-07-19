#!/usr/bin/env python

from __future__ import print_function

import logging

import sys
import os
import io
import traceback

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

class Colors(int, Enum):
    DEFAULT = 1
    STDOUT = 2
    STDERR = 3
    INFO = 4
    WARNING = 5
    ERROR = 6
    CRITICAL = 7
    DEBUG = 8

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
    color_map = {
        logging.INFO: Colors.INFO,
        logging.WARNING: Colors.WARNING,
        logging.ERROR: Colors.ERROR,
        logging.CRITICAL: Colors.CRITICAL,
        logging.DEBUG: Colors.DEBUG
    }

    def __init__(self, window):
        logging.Handler.__init__(self)
        self.window = window

    def emit(self, record):
        self.acquire()
        try:
            color_idx = self.color_map.get(record.levelno, Colors.DEFAULT)
            color_idx = record.__dict__.get('color', color_idx)
            color = curses.color_pair(color_idx)
            self.window.addstr('\n')
            self.window.addstr(str(record.getMessage()), color)
        finally:
            self.release()

class StdioWrapper:

    def __init__(self, level):
        self.level = level

    def write(self, string):
        log = logging.getLogger('output')
        ts = datetime.now().strftime('%x')
        string = string.replace('\n', '\n{}:'.format(ts))

        color = Colors.STDERR if self.level == logging.ERROR else Colors.STDOUT

        log.log(self.level, '{}: {}'.format(ts, string), extra=dict(color=color))

    def flush(self):
        pass

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

    @property
    def output(self):
        return logging.getLogger('output')
    

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
            self.output.info(text)

    def cmd_init(self):
        if self.client is not None:
            self.client.init()
        else:
            print('MTProto client has not yet been created', file=sys.stderr)

    def cmd_quit(self):
        print('exiting...', file=sys.stderr)
        self.done = True

    def cmd_switch_to_eval_mode(self):
        ps1_win = self.windows['ps1']

        self.mode = CursesCLI.EVAL_MODE
        self.ps1_text = 'twx.mtproto#'
        ps1_win.clear()
        ps1_win.addstr(self.ps1_text)

        print("Now in eval mode. Enter '$' to return to command mode")

    def cmd_switch_to_command_mode(self):
        ps1_win = self.windows['ps1']

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

    def init_colors(self):
        curses.use_default_colors()

        curses.init_pair(Colors.DEFAULT.value, -1, -1)
        curses.init_pair(Colors.STDOUT.value, curses.COLOR_CYAN, -1)
        curses.init_pair(Colors.STDERR.value, curses.COLOR_WHITE, curses.COLOR_RED)
        curses.init_pair(Colors.INFO.value, -1, -1)
        curses.init_pair(Colors.WARNING.value, curses.COLOR_YELLOW, -1)
        curses.init_pair(Colors.ERROR.value, curses.COLOR_RED, -1)
        curses.init_pair(Colors.CRITICAL.value, curses.COLOR_WHITE, curses.COLOR_MAGENTA)
        curses.init_pair(Colors.DEBUG.value, curses.COLOR_MAGENTA, -1)

    def init_windows(self):
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

        window_handler = WindowLogHandler(output_win)
        window_handler.setLevel(logging.DEBUG)

        output = logging.getLogger('output')
        output.addHandler(window_handler)
        output.setLevel(logging.DEBUG)

        cy, cx = output_win.getmaxyx()
        self.windows['separator'] = root_win.derwin(1, cx, cy, 0)
        separator_win = self.windows['separator']
        separator_win.hline(0, 0, '-', x)

        self.windows['ps1'] = root_win.derwin(1, len(self.ps1_text)+1, height-1, 0)
        ps1_win = self.windows['ps1']
        ps1_win.addstr(self.ps1_text)

        cy, cx = ps1_win.getmaxyx()
        self.windows['input'] = root_win.derwin(1, width - cx, height-1, cx)
        input_win = self.windows['input']
        input_win.move(0, 0)
        input_win.keypad(1)

    @asyncio.coroutine
    def _curses_refresh(self):
        self.init_colors()
        self.init_windows()

        stderr_wrapper = StdioWrapper(logging.INFO)
        stdout_wrapper = StdioWrapper(logging.ERROR)

        set_stdio(stdout_wrapper, stderr_wrapper)

        parser = argparse.ArgumentParser()
        parser.add_argument('--config', type=argparse.FileType(), default='mtproto.conf')
        args = parser.parse_args()

        config = ConfigParser()
        config.read_file(args.config)
        
        self.create_client(config)

        buf = list()

        for name, win in self.windows.items():
            win.noutrefresh()
        curses.doupdate()

        while not self.done:
            input_win = self.windows['input']
            try:
                key = input_win.getkey()
                if key == '\n':
                    string = ''.join(buf).strip()

                    if string.strip():
                        self.add_cmd_history(buf)
                        self.output.info('{} {}'.format(self.ps1_text, string))
                    else:
                        self.output.info('')

                    buf = list()
                    input_win.clear()
                    self.process_input(string)
                elif key == '\x7f':
                    cy, cx = input_win.getyx()
                    if 0 < cx <= len(buf):
                        del buf[cx-1]
                        input_win.move(cy, cx-1)
                elif key == '\x15':
                    cy, cx = input_win.getyx()
                    if 0 < cx:
                        if cx < len(buf):
                            del buf[0:cx]
                        else:
                            buf = list()
                        input_win.move(0, 0)
                elif key == 'KEY_LEFT':
                    cy, cx = input_win.getyx()
                    if 0 < cx:
                        input_win.move(cy, cx-1)
                elif key == 'KEY_RIGHT':
                    cy, cx = input_win.getyx()
                    if cx < len(buf):
                        input_win.move(cy, cx+1)
                elif key == 'KEY_UP':
                    buf = self.prev_cmd_history(buf)
                    input_win.move(0, len(buf))
                elif key == 'KEY_DOWN':
                    buf = self.next_cmd_history(buf)
                    input_win.move(0, len(buf))
                elif key == 'KEY_RESIZE':
                    # TODO: resize
                    ...
                elif len(key) == 1 and key.isprintable():
                    cy, cx = input_win.getyx()
                    if 0 <= cx < 255 and len(buf) < 255:
                        buf.insert(cx, key)
                        input_win.move(cy, cx+1)
                else:
                    self.output.debug('unhandled key: \'{}\''.format(repr(key)))

                cy, cx = input_win.getyx()
                input_win.clear()

                input_win.addstr(''.join(buf))
                input_win.move(cy, cx)

                for name, win in self.windows.items():
                    win.noutrefresh()
                curses.doupdate()
            except Exception as e:
                exc_info = sys.exc_info()
                fmt = traceback.format_exception(exc_info[0], exc_info[1], exc_info[2])
                self.output.critical(''.join(fmt).rstrip())
            except KeyboardInterrupt as e:
                return 130

    def run_curses(self, stdscr):
        self.windows['stdscr'] = stdscr

        loop = asyncio.get_event_loop()
        self.exit_code = loop.run_until_complete(self._curses_refresh())
        loop.close()

    def run(self):
        locale.setlocale(locale.LC_ALL, '')
        curses.wrapper(self.run_curses)
        reset_stdio()
        return self.exit_code

def main():
    return CursesCLI().run()

if __name__ == "__main__":
    sys.exit(main())
