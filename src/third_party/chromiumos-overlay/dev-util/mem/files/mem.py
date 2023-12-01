#!/usr/bin/env python3

# Copyright 2014 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.


"""Access memory using /dev/mem.

Can be used as a command-line tool or via 'import mem' in python.
"""


import argparse
import code
import inspect
import mmap
import struct
import sys


_BANNER = """Welcome to mem interactive mode (featuring python!)

Available functions:
"""


class HexInt(int):
  """An int that prints out as hex but is still just a number."""

  def __repr__(self):
    try:
      width = getattr(self, 'width')
    except AttributeError:
      width = 4
    return '%#0*x' % (2 * width + 2, self)

  def __str__(self):
    return repr(self)


def rm(addr, nbytes):
  """Read memory at the given addr as a string.

  Args:
    addr: The address to read at.
    nbytes: The number of bytes to read.

  Returns:
    The string that was read.
  """
  with open('/dev/mem', 'r+b') as mem:
    offset = addr & 0xfff
    mem_map = mmap.mmap(mem.fileno(), nbytes + offset, offset=addr & ~0xfff)
    return mem_map[offset:offset + nbytes]


def wm(addr, val):
  """Write a string to memory at the given addr.

  Args:
    addr: The address to read at.
    val: A string to write.
  """
  with open('/dev/mem', 'r+b') as mem:
    nbytes = len(val)
    offset = addr & 0xfff
    mem_map = mmap.mmap(mem.fileno(), nbytes + offset, offset=addr & ~0xfff)
    mem_map[offset:offset + nbytes] = val


def r(addr):
  """Read a single 32-bit word (little endian).

  Args:
    addr: The address to read at.

  Returns:
    The value that was read; returns as a HexInt (a subclass of long) so that
    it by default prints itself in hex.  You can use this like any other int.
  """
  return HexInt(struct.unpack('<I', rm(addr, 4))[0])


def w(addr, val):
  """Write a single 32-bit word (little endian).

  Args:
    addr: The address to write to.
    val:  The value to write.
  """
  wm(addr, struct.pack('<I', val))


def _ParseInt(x):
  """Create an int from a string, autodetecting the base."""
  return int(x, 0)


# Commands we export and their argument types.
_COMMANDS = {
    'r': [_ParseInt],
    'w': [_ParseInt, _ParseInt],
    'rm': [_ParseInt, _ParseInt],
    'wm': [_ParseInt, str],
}


def _ListCommands():
  """Return a list of commands as a string.

  Returns:
    A string that can be printed to the user.
  """
  commands = []

  for cmd_name in sorted(_COMMANDS.keys()):
    func = eval(cmd_name)
    arg_names = inspect.signature(func).parameters
    short_doc = func.__doc__.splitlines()[0]

    arg_string = ', '.join(arg_names)
    commands.append('- %s(%s) # %s' % (cmd_name, arg_string, short_doc))

  return '\n'.join(commands)


def _CreateParser():
  """Create an argparse object we can use.

  Returns:
    An argparse object that can be used to parse our options.
  """
  parser = argparse.ArgumentParser()
  subparsers = parser.add_subparsers()

  for cmd_name, arg_types in sorted(_COMMANDS.items()):
    func = eval(cmd_name)
    arg_names = inspect.signature(func).parameters
    short_doc = func.__doc__.splitlines()[0]

    # Get descriptions out assuming single-line descs.
    arg_descs = {}
    for line in func.__doc__.splitlines():
      line = line.strip()
      arg_name = line.split(':')[0]
      if arg_name in arg_names:
        arg_descs[arg_name] = line.partition(':')[-1]

    subparser = subparsers.add_parser(cmd_name, help=short_doc)
    for arg_name, arg_type in zip(arg_names, arg_types):
      subparser.add_argument(arg_name, type=arg_type,
                             help=arg_descs[arg_name])
      subparser.set_defaults(func=func)

  return parser


def main(args=None):
  if args is None:
    args = sys.argv[1:]

  if not args:
    # Try to pretend that they ran python -i to just use us interactively.
    return code.interact(banner=_BANNER + _ListCommands(), local=globals())

  parser = _CreateParser()
  try:
    # Parse args and get back something we can use to call the function.
    namespace = parser.parse_args(args)
    func_kwargs = vars(namespace).copy()
    func = func_kwargs.pop('func')

    result = func(**func_kwargs)

    # Print the result; no trailing return if we're not on a tty.
    if result is not None:
      print(result, end='\n' if sys.stdout.isatty() else '')
  except Exception as e:
    # For now really simple error handling...
    parser.error(str(e))

    return 1
  return 0


if __name__ == '__main__':
  sys.exit(main(sys.argv[1:]))
