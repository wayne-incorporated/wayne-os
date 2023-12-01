#!/usr/bin/python
# Copyright 2016 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""This script wraps the go cross compilers.

It ensures that Go binaries are linked with an external linker
by default (cross gcc). Appropriate flags are added to build a
position independent executable (PIE) for ASLR.
"export GOPIE=0" to temporarily disable this behavior.
"""

import os
import sys

# The following values are filled in by the ebuild at installation time:
GOARCH = '@GOARCH@'
CC = '@CC@'
CXX = '@CXX@'
GOTOOL = '@GOTOOL@'


def has_ldflags(argv):
  """Check if any linker flags are present in argv."""
  link_flags = set(('-ldflags', '-linkmode', '-buildmode',
                    '-installsuffix', '-extld', '-extldflags'))
  if set(argv) & link_flags:
    return True
  for arg in argv:
    for link_flag in link_flags:
      if arg.startswith(link_flag + '='):
        return True
  return False


def main(argv):
  pie_enabled = os.getenv('GOPIE', '1') != '0'

  if len(argv) and pie_enabled and not has_ldflags(argv):
    if argv[0] in ('build', 'install', 'run', 'test'):
      # Add "-buildmode=pie" to "go build|install|run|test" commands.
      argv = argv[0:1] + ['-buildmode=pie'] + argv[1:]
    elif argv[0] == 'tool' and len(argv) > 1:
      if argv[1] == 'asm':
        # Handle direct assembler invocations ("go tool asm <args>").
        argv = argv[0:2] + ['-shared'] + argv[2:]
      elif argv[1] == 'compile':
        # Handle direct compiler invocations ("go tool compile <args>").
        argv = argv[0:2] + ['-shared', '-installsuffix=shared'] + argv[2:]
      elif argv[1] == 'link':
        # Handle direct linker invocations ("go tool link <args>").
        argv = argv[0:2] + ['-installsuffix=shared', '-buildmode=pie',
                            '-extld', CC] + argv[2:]

  os.environ['GOOS'] = 'linux'
  os.environ['GOARCH'] = GOARCH
  os.environ.setdefault('CGO_ENABLED', '1')
  os.environ['CC'] = CC
  os.environ['CXX'] = CXX
  os.execv(GOTOOL, [GOTOOL] + argv)


if __name__ == '__main__':
  main(sys.argv[1:])
