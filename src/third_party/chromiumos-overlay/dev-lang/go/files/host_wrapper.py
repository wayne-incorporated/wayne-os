#!/usr/bin/python
# Copyright 2016 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""This script wraps the go host compiler.

It sets the correct environment variables for host builds.
"""

import os
import sys

# The following values are filled in by the ebuild at installation time:
GOARCH = '@GOARCH@'
CC = '@CC@'
CXX = '@CXX@'
GOTOOL = '@GOTOOL@'


def main(argv):
  os.environ['GOOS'] = 'linux'
  os.environ['GOARCH'] = GOARCH
  os.environ.setdefault('CGO_ENABLED', '1')
  os.environ['CC'] = CC
  os.environ['CXX'] = CXX
  os.execv(GOTOOL, [GOTOOL] + argv)


if __name__ == '__main__':
  main(sys.argv[1:])
