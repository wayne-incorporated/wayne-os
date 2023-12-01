#!/usr/bin/env python3
# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Wrapper of pkg-config like command line to format output for gn.

Parses the output and filter the flags with a certain prefix like "-l", "-L",
so that it can be used in GN files easily.

Usage:
  arg_prefix_filter_wrapper.py --prefix=-l gtest-config --libs
"""

import argparse
import shlex
import subprocess
import sys


def get_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", type=str, default="-l")
    return parser


def main(argv):
    parser = get_parser()
    opts, cmd_list = parser.parse_known_args(argv)

    prefix_len = len(opts.prefix)
    flags = shlex.split(subprocess.check_output(cmd_list, encoding="utf-8"))
    filtered = [x[prefix_len:] for x in flags if x.startswith(opts.prefix)]
    print("\n".join(filtered))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
