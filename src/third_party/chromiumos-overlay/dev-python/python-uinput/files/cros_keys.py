# Copyright 2015 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import argparse
# Get all evdev/uinput events in our namespace.
# pylint: disable=wildcard-import, unused-wildcard-import
from uinput.ev import *
import subprocess
import time
import uinput


# Time to wait after uinput device creation, before starting to type. This is
# needed as kernel/Chrome takes some time to register the new input device.
#
# TODO(crbug.com/714950): This is a hack, we should figure out a way to check
# when kernel/Chrome is ready (monitor udev events?), instead of waiting for
# an arbitrary amount of time.
STARTUP_DELAY = 0.2

# Default delay between key presses in seconds. 12ms is the xdotool default.
DEFAULT_DELAY = 0.012

uinput_device_keyboard = None


# This dictionary contains most 7 bit ASCII characters. Add more if needed.
# TODO(ihf): Create this table using xkbcommon to support arbirtrary
# character sets and keyboard layouts.
_CROS_CHAR_MAP = {
    "\b": [KEY_BACKSPACE],
    "\t": [KEY_TAB],
    "\n": [KEY_ENTER],

    " ":  [KEY_SPACE],
    "!":  [KEY_LEFTSHIFT, KEY_1],
    '"':  [KEY_LEFTSHIFT, KEY_APOSTROPHE],
    "#":  [KEY_LEFTSHIFT, KEY_3],
    "$":  [KEY_LEFTSHIFT, KEY_4],
    "%":  [KEY_LEFTSHIFT, KEY_5],
    "&":  [KEY_LEFTSHIFT, KEY_7],
    "'":  [KEY_APOSTROPHE],
    "(":  [KEY_LEFTSHIFT, KEY_9],
    ")":  [KEY_LEFTSHIFT, KEY_0],
    "*":  [KEY_KPASTERISK],
    "+":  [KEY_LEFTSHIFT, KEY_EQUAL],
    ",":  [KEY_COMMA],
    "-":  [KEY_MINUS],
    ".":  [KEY_DOT],
    "/":  [KEY_SLASH],

    "0":  [KEY_0],
    "1":  [KEY_1],
    "2":  [KEY_2],
    "3":  [KEY_3],
    "4":  [KEY_4],
    "5":  [KEY_5],
    "6":  [KEY_6],
    "7":  [KEY_7],
    "8":  [KEY_8],
    "9":  [KEY_9],

    ":":  [KEY_LEFTSHIFT, KEY_SEMICOLON],
    ";":  [KEY_SEMICOLON],
    "<":  [KEY_LEFTSHIFT, KEY_COMMA],
    "=":  [KEY_EQUAL],
    ">":  [KEY_LEFTSHIFT, KEY_DOT],
    "?":  [KEY_LEFTSHIFT, KEY_SLASH],
    "@":  [KEY_LEFTSHIFT, KEY_2],

    "A":  [KEY_LEFTSHIFT, KEY_A],
    "B":  [KEY_LEFTSHIFT, KEY_B],
    "C":  [KEY_LEFTSHIFT, KEY_C],
    "D":  [KEY_LEFTSHIFT, KEY_D],
    "E":  [KEY_LEFTSHIFT, KEY_E],
    "F":  [KEY_LEFTSHIFT, KEY_F],
    "G":  [KEY_LEFTSHIFT, KEY_G],
    "H":  [KEY_LEFTSHIFT, KEY_H],
    "I":  [KEY_LEFTSHIFT, KEY_I],
    "J":  [KEY_LEFTSHIFT, KEY_J],
    "K":  [KEY_LEFTSHIFT, KEY_K],
    "L":  [KEY_LEFTSHIFT, KEY_L],
    "M":  [KEY_LEFTSHIFT, KEY_M],
    "N":  [KEY_LEFTSHIFT, KEY_N],
    "O":  [KEY_LEFTSHIFT, KEY_O],
    "P":  [KEY_LEFTSHIFT, KEY_P],
    "Q":  [KEY_LEFTSHIFT, KEY_Q],
    "R":  [KEY_LEFTSHIFT, KEY_R],
    "S":  [KEY_LEFTSHIFT, KEY_S],
    "T":  [KEY_LEFTSHIFT, KEY_T],
    "U":  [KEY_LEFTSHIFT, KEY_U],
    "V":  [KEY_LEFTSHIFT, KEY_V],
    "W":  [KEY_LEFTSHIFT, KEY_W],
    "X":  [KEY_LEFTSHIFT, KEY_X],
    "Y":  [KEY_LEFTSHIFT, KEY_Y],
    "Z":  [KEY_LEFTSHIFT, KEY_Z],

    "[":  [KEY_LEFTBRACE],
    "\\": [KEY_BACKSLASH],
    "]":  [KEY_RIGHTBRACE],
    "^":  [KEY_LEFTSHIFT, KEY_6],
    "_":  [KEY_LEFTSHIFT, KEY_MINUS],
    "`":  [KEY_GRAVE],

    "a":  [KEY_A],
    "b":  [KEY_B],
    "c":  [KEY_C],
    "d":  [KEY_D],
    "e":  [KEY_E],
    "f":  [KEY_F],
    "g":  [KEY_G],
    "h":  [KEY_H],
    "i":  [KEY_I],
    "j":  [KEY_J],
    "k":  [KEY_K],
    "l":  [KEY_L],
    "m":  [KEY_M],
    "n":  [KEY_N],
    "o":  [KEY_O],
    "p":  [KEY_P],
    "q":  [KEY_Q],
    "r":  [KEY_R],
    "s":  [KEY_S],
    "t":  [KEY_T],
    "u":  [KEY_U],
    "v":  [KEY_V],
    "w":  [KEY_W],
    "x":  [KEY_X],
    "y":  [KEY_Y],
    "z":  [KEY_Z],

    "{": [KEY_LEFTSHIFT, KEY_LEFTBRACE],
    "|": [KEY_LEFTSHIFT, KEY_BACKSLASH],
    "}": [KEY_LEFTSHIFT, KEY_RIGHTBRACE],
    "~": [KEY_LEFTSHIFT, KEY_GRAVE],
}


# A list of American English ChromeOS keys to define a keyboard device.
_CROS_KEYS_ALL = [
    # Function row.
    KEY_ESC,
    KEY_F1,
    KEY_F2,
    KEY_F3,
    KEY_F4,
    KEY_F5,
    KEY_F6,
    KEY_F7,
    KEY_F8,
    KEY_F9,
    KEY_F10,
    KEY_F11,
    KEY_F12,
    KEY_HOME,
    KEY_END,
    KEY_INSERT,
    KEY_DELETE,
    # First row.
    KEY_GRAVE,
    KEY_1,
    KEY_2,
    KEY_3,
    KEY_4,
    KEY_5,
    KEY_6,
    KEY_7,
    KEY_8,
    KEY_9,
    KEY_0,
    KEY_MINUS,
    KEY_EQUAL,
    KEY_BACKSPACE,
    # Second row.
    KEY_TAB,
    KEY_Q,
    KEY_W,
    KEY_E,
    KEY_R,
    KEY_T,
    KEY_Y,
    KEY_U,
    KEY_I,
    KEY_O,
    KEY_P,
    KEY_LEFTBRACE,
    KEY_RIGHTBRACE,
    KEY_BACKSLASH,
    # Third row
    KEY_CAPSLOCK,
    KEY_A,
    KEY_S,
    KEY_D,
    KEY_F,
    KEY_G,
    KEY_H,
    KEY_J,
    KEY_K,
    KEY_L,
    KEY_SEMICOLON,
    KEY_APOSTROPHE,
    KEY_ENTER,
    # Forth row.
    KEY_LEFTSHIFT,
    KEY_102ND,
    KEY_Z,
    KEY_X,
    KEY_C,
    KEY_V,
    KEY_B,
    KEY_N,
    KEY_M,
    KEY_COMMA,
    KEY_DOT,
    KEY_SLASH,
    KEY_RIGHTSHIFT,
    # Fifth row.
    KEY_LEFTCTRL,
    KEY_FN,
    KEY_SEARCH,
    KEY_LEFTALT,
    KEY_SPACE,
    KEY_NUMLOCK,
    KEY_SCROLLLOCK,
    KEY_RIGHTALT,
    KEY_RIGHTCTRL,
    # Directional keys.
    KEY_UP,
    KEY_PAGEUP,
    KEY_LEFT,
    KEY_RIGHT,
    KEY_DOWN,
    KEY_PAGEDOWN,
]


def _chars_to_events(chars):
    """
    Translates string to key events.

    @param chars: characters to translate to events.
    @returns: list of lists of events representing characters.
    """
    events = []
    for char in chars:
        events.append(_CROS_CHAR_MAP[char])
    return events


def _get_uinput_device_keyboard():
    """
    Lazy initialize device and return it. We don't want to create a device
    during build_packages or for tests that don't need it, hence init with None.
    """
    global uinput_device_keyboard
    if uinput_device_keyboard is None:
        # For DUTs without keyboard attached force load uinput.
        subprocess.Popen(['modprobe', 'uinput']).wait()
        uinput_device_keyboard = uinput.Device(_CROS_KEYS_ALL)
        time.sleep(STARTUP_DELAY)
    return uinput_device_keyboard


def _uinput_translate_name(event_name):
    """
    Translates string |event_name| to uinput event.
    """
    return getattr(uinput, event_name)


def _uinput_emit_keycombo(device, events, syn=True):
    """
    Wrapper for uinput.emit_combo. Emits sequence of events.
    Example: [KEY_LEFTCTRL, KEY_LEFTALT, KEY_F5]
    """
    time.sleep(DEFAULT_DELAY)
    device.emit_combo(events, syn)


def press_keys(keys):
    """Presses the given keys as one combination.

    Please do not leak uinput dependencies outside of the file.

    @param key: A simple list of key strings, e.g. ['LEFTCTRL', 'F4']
    """
    events =  [_uinput_translate_name(en) for en in keys]
    _uinput_emit_keycombo(_get_uinput_device_keyboard(), events)


def type_chars(text):
    """Translates ASCII text to keystrokes and sends them as events.

    @param text: string to send as events to keyboard.
    """
    events = _chars_to_events(text)
    device = _get_uinput_device_keyboard()
    for keys in events:
        _uinput_emit_keycombo(device, keys)
