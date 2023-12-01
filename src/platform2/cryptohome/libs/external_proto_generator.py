#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Copies proto files into the destination directory with proper modification.

For example, `./external_proto_generator.py -o foo a.proto b.proto` will
generate foo/a.proto and foo/b.proto.
"""

from __future__ import print_function

import argparse
import sys
import os


def get_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "-o", dest="out_dir", required=True, help="output directory"
    )
    parser.add_argument("inputs", nargs="*")
    return parser


def main(argv):
    parser = get_parser()
    opts = parser.parse_args(argv)

    for input_path in opts.inputs:
        output_path = os.path.join(opts.out_dir, os.path.basename(input_path))
        with open(input_path, "r") as f:
            code = f.read()
        code = code.replace("LITE_RUNTIME", "CODE_SIZE")
        with open(output_path, "w") as f:
            f.write(code)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
