#!/usr/bin/env python3
# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Python script to generate a .pc file from gn.

This scripts fills the fields of the .pc file with the given values of
the flags.
For detailed meaning of each field, please find it in
https://people.freedesktop.org/~dbn/pkg-config-guide.html#concepts

Example:

python generate-pc.py \
  --output="${target}.pc" \
  --name="${libname}" \
  --description="${description}" \
  --version="${version}" \
  --requires="${requires}"
  ...
"""

# TODO(crbug.com/868820): chromite.lib.commandline may be a good alternate
# but is concerned the loading performance. Considering this is a part of
# configuration, use argparse in standard library. Replace it when the loading
# gets enough fast.
import argparse
import sys


_TEMPLATE = """
Name: %(name)s
Description: %(description)s
Version: %(version)s
Requires: %(requires)s
Requires.private: %(requires_private)s
Libs: %(libs)s
Libs.private: %(libs_private)s
Cflags: %(cflags)s
"""


def _generate(output, params):
    """Generates a .pc file.

    Args:
        output: Path to the output file.
        params: an object containing the .pc file data. It should have the
            following members: name, description, version, requires,
            requies_private, libs, libs_private and cflags.
    """
    with open(output, "w") as f:
        f.write(
            _TEMPLATE.lstrip("\n")
            % {
                "name": params.name,
                "description": params.description,
                "version": params.version,
                "requires": " ".join(params.requires),
                "requires_private": " ".join(params.requires_private),
                "libs": " ".join(params.libs),
                "libs_private": " ".join(params.libs_private),
                "cflags": " ".join(params.cflags),
            }
        )


def _get_parser():
    """Returns an argument parser for this script."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, help="The output file name")
    parser.add_argument("--name", required=True, help="The library name")
    parser.add_argument(
        "--description", default="", help="The description of the library"
    )
    parser.add_argument(
        "--version", required=True, help="The version of the library"
    )
    parser.add_argument(
        "--requires", action="append", default=[], help="Packages for Required"
    )
    parser.add_argument(
        "--requires-private",
        action="append",
        default=[],
        help="Packages for Required.private",
    )
    parser.add_argument(
        "--libs", action="append", default=[], help="Libraries for Libs"
    )
    parser.add_argument(
        "--libs-private",
        action="append",
        default=[],
        help="Libraries for Libs.private",
    )
    parser.add_argument(
        "--cflags", action="append", default=[], help="Compiler flags"
    )
    return parser


def main(argv):
    parser = _get_parser()
    options = parser.parse_args(argv)
    _generate(options.output, options)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
