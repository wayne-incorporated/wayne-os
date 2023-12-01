#!/usr/bin/env python3
# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Python wrapper for programs to generate args.

GN exec_script runs the script with python. For running a program other than
python, use this wrapper.

path/to/args_generator_wrapper.py program arg1 ...
will run the program with the args.

Since the intention of this wrapper is to generate arguments passed to the
shell, the output of the program is unescaped by the shell and spaces in it
are replaced with newlines.
"""

import subprocess
import sys

import common_utils


output = subprocess.check_output(sys.argv[1:], encoding="utf-8").strip()
unescaped = common_utils.parse_shell_args(output)

print("\n".join(unescaped))
