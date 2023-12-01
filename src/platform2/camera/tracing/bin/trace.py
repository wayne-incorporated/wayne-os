#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""A tool to instrument tracing (remotely) on a DUT."""

import argparse
import importlib
import importlib.abc
import importlib.machinery
import logging
import os
import sys


_CROS_CAMERA_TOOLS_TRACING_PATH = os.path.dirname(os.path.realpath(__file__))


# pylint: disable=abstract-method
class CrOSCameraLoader(importlib.abc.Loader):
    """Virtual cros_camera_tracing module."""

    def create_module(self, spec):
        """Load the current dir."""

        path, mod = os.path.split(_CROS_CAMERA_TOOLS_TRACING_PATH)
        sys.path.insert(0, path)
        try:
            return importlib.import_module(mod)
        finally:
            sys.path.remove(path)

    def exec_module(self, spec):
        """Required stub as a loader."""


class CrOSCameraFinder(importlib.abc.MetaPathFinder):
    """Virtual cros_camera_tracing finder."""

    def __init__(self, loader):
        self._loader = loader

    # pylint: disable=unused-argument
    def find_spec(self, fullname, path=None, target=None):
        if fullname != "cros_camera_tracing":
            return None
        return importlib.machinery.ModuleSpec(fullname, self._loader)


# Set up meta path for for `cros_camera_tracing` virtual module.
sys.meta_path.insert(0, CrOSCameraFinder(CrOSCameraLoader()))

# pylint: disable=wrong-import-position, import-error
from cros_camera_tracing import record
from cros_camera_tracing import report


def init_logging(args):
    log_level = logging.INFO
    if args.debug:
        log_level = logging.DEBUG
    logging.basicConfig(
        level=log_level, format="%(asctime)s %(levelname)s: %(message)s"
    )


def main(argv: list):
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--debug", action="store_true", help="Enable debug logs"
    )

    subparsers = parser.add_subparsers(title="subcommands", dest="subcmd")
    record.set_up_subcommand_parser(subparsers)
    report.set_up_subcommand_parser(subparsers)

    args = parser.parse_args(argv)

    init_logging(args)

    if args.subcmd == "record":
        record.execute_subcommand(args)
    elif args.subcmd == "report":
        report.execute_subcommand(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
