#!/usr/bin/env python3
# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Python script to output the given list as a space-delimited string to a file.

path/to/write_args.py --output filename -- arg1 arg2 ...
will output the args to the file.

This script is used from common-mk/deps.gni .
TODO(oka): Remove this file and replace the invocation with write_file if
space-delimiting option is added to it.
https://bugs.chromium.org/p/gn/issues/detail?id=9
"""

import argparse
import sys


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, help="the output file name")
    parser.add_argument("args", nargs="*")
    options = parser.parse_args(argv)

    with open(options.output, "w", encoding="utf-8") as f:
        f.write(" ".join(options.args) + "\n")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
