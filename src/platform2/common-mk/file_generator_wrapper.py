#!/usr/bin/env python3
# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Python wrapper for programs to generate files.

GN action and action_foreach run the script with python. For running a program
other than python, use this wrapper.

path/to/file_generator_wrapper.py program arg1 ...
will run the program with the args.
"""

import subprocess
import sys


subprocess.check_call(sys.argv[1:])
