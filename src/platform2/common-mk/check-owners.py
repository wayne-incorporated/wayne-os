#!/usr/bin/env python3
# Copyright 2019 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Linter for various OWNERS files."""

import logging
from pathlib import Path
import sys


TOP_DIR = Path(__file__).resolve().parent.parent

# Find chromite!
sys.path.insert(0, str(TOP_DIR.parent.parent))

# pylint: disable=wrong-import-position
from chromite.lib import commandline
from chromite.lib import git


# pylint: enable=wrong-import-position


def GetActiveProjects():
    """Return the list of active projects."""
    # Look at all the paths (files & dirs) in the top of the git repo.  This way
    # we ignore local directories devs created that aren't actually committed.
    cmd = ["ls-tree", "--name-only", "-z", "HEAD"]
    result = git.RunGit(TOP_DIR, cmd)

    # Split the output on NULs to avoid whitespace/etc... issues.
    paths = result.stdout.split("\0")

    # ls-tree -z includes a trailing NUL on all entries, not just seperation,
    # so filter it out if found (in case ls-tree behavior changes on us).
    for path in [Path(x) for x in paths if x]:
        if (TOP_DIR / path).is_dir():
            yield path


def CheckSubdirs():
    """Check the subdir OWNERS files exist."""
    ret = 0
    for proj in GetActiveProjects():
        path = TOP_DIR / proj / "OWNERS"
        if not path.exists():
            logging.error('*** Project "%s" needs an OWNERS file', proj)
            ret = 1
            continue

        data = path.read_text()
        for i, line in enumerate(data.splitlines(), start=1):
            if line.strip().startswith("set noparent"):
                logging.error(
                    '*** %s:%i: Do not use "noparent" in top level projects',
                    path,
                    i,
                )
                ret = 1

            if line.strip() != line:
                logging.error(
                    "*** %s:%i: Trim leading/trailing whitespace", path, i
                )
                ret = 1

        if not data:
            logging.error("*** %s: File is empty", path)
            ret = 1

        if not data.endswith("\n"):
            logging.error("*** %s: Missing trailing newline", path)
            ret = 1

        if data.startswith("\n"):
            logging.error("*** %s: Trim leading blanklines", path)
            ret = 1

        if data.endswith("\n\n"):
            logging.error("*** %s: Trim trailing blanklines", path)
            ret = 1

    return ret


def GetParser():
    """Return an argument parser."""
    parser = commandline.ArgumentParser(description=__doc__)
    return parser


def main(argv):
    """The main func!"""
    parser = GetParser()
    opts = parser.parse_args(argv)
    opts.Freeze()

    return CheckSubdirs()


if __name__ == "__main__":
    commandline.ScriptWrapperMain(lambda _: main)
