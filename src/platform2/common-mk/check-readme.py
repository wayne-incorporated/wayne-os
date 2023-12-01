#!/usr/bin/env python3
# Copyright 2017 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Linter for various README.md files."""

import difflib
import logging
import os
import re
import sys


TOP_DIR = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

# Find chromite!
sys.path.insert(0, os.path.join(TOP_DIR, "..", ".."))

# pylint: disable=wrong-import-position
from chromite.lib import commandline
from chromite.lib import git
from chromite.lib import osutils


# pylint: enable=wrong-import-position


def GetActiveProjects():
    """Return the list of active projects."""
    # Look at all the paths (files & dirs) in the top of the git repo. This way
    # we ignore local directories devs created that aren't actually committed.
    cmd = ["ls-tree", "--name-only", "-z", "HEAD"]
    result = git.RunGit(TOP_DIR, cmd)

    # Split the output on NULs to avoid whitespace/etc... issues.
    paths = result.stdout.split("\0")

    # ls-tree -z will include a trailing NUL on all entries, not just
    # separation, so filter it out if found (in case ls-tree behavior changes
    # on us).
    for path in [x for x in paths if x]:
        if os.path.isdir(os.path.join(TOP_DIR, path)):
            yield path


def CheckTopLevel():
    """Check the top level README.md list."""
    ret = 0
    path = os.path.join(TOP_DIR, "README.md")
    data = osutils.ReadFile(path).splitlines()

    # Look for the directory header.
    try:
        i = data.index("# Local Project Directory")
    except ValueError:
        logging.error("README.md index out of sync")
        return 1
    data = data[i + 1 :]

    # Pull out all the linked projects.
    listed_projs = []
    listed_dirs = []
    for line in data:
        # Break once we hit the end of the table.
        if line.startswith("#"):
            break

        m = re.match(r"^[|] \[([^]]+)*\]\(\./([^)]*)/\)", line)
        if m:
            listed_projs.append(m.group(1))
            listed_dirs.append(m.group(2))
    logging.debug("README.md projects: %s", listed_projs)

    sorted_projs = sorted(listed_projs)
    if listed_projs != sorted_projs:
        ret = 1
        lines = list(
            difflib.unified_diff(listed_projs, sorted_projs, lineterm="")
        )
        logging.error(
            "README.md project listing should be kept sorted:\n%s",
            "\n".join(lines[2:]),
        )

    # Check the list in README.md for outdated entries.
    old_dirs = []
    for project_dir in listed_dirs:
        path = os.path.join(TOP_DIR, project_dir)
        if not os.path.isdir(path):
            old_dirs.append(path)
    if old_dirs:
        ret = 1
        logging.error("README.md: found stale project entries: %s", old_dirs)

    # Check the local source repo for missing entries.
    existing_projs = sorted(GetActiveProjects())
    logging.debug("Found active projects: %s", existing_projs)
    new_projs = []
    for proj in existing_projs:
        path = os.path.join(TOP_DIR, proj)
        if os.path.isdir(path) and proj not in listed_projs:
            new_projs.append(proj)
    if new_projs:
        ret = 1
        logging.error("README.md: document new projects: %s", new_projs)

    return ret


def CheckSubdirs():
    """Check the subdir README.md files exist."""
    # Legacy projects that don't have a README.md file.
    # Someone should write some docs :D.
    LEGACYLIST = (
        "attestation",  # TODO(b/262375413)
        "avtest_label_detect",
        "cros-disks",  # TODO(b/262376624)
        "image-burner",
        "init",
        "libchromeos-ui",
        "libcontainer",
        "modem-utilities",
        "mtpd",  # TODO(b/262376388)
        "timberslide",
        "tpm_manager",  # TODO(b/262375897)
        "trim",
    )

    ret = 0
    for proj in GetActiveProjects():
        readme = os.path.join(TOP_DIR, proj, "README.md")
        if os.path.exists(readme):
            if proj in LEGACYLIST:
                logging.error(
                    '*** Project "%s" is in no-README LEGACYLIST, but '
                    "actually has one. Please remove it from "
                    "LEGACYLIST!",
                    proj,
                )
        else:
            if not proj in LEGACYLIST:
                logging.error('*** Project "%s" needs a README.md file', proj)
                ret = 1

    # Make sure the list doesn't get stale itself.
    old_projects = set(LEGACYLIST) - set(GetActiveProjects())
    if old_projects:
        logging.error(
            "*** %s:LEGACYLIST contains old entries %s.  Please remove them.",
            __file__,
            old_projects,
        )
        ret = 1

    return ret


def GetParser():
    """Return an argument parser."""
    parser = commandline.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--extensions",
        default="gyp,gypi",
        help="Comma delimited file extensions to check. "
        "(default: %(default)s)",
    )
    parser.add_argument("files", nargs="*", help="Files to run lint.")
    return parser


def main(argv):
    parser = GetParser()
    opts = parser.parse_args(argv)
    opts.Freeze()

    return CheckTopLevel() | CheckSubdirs()


if __name__ == "__main__":
    commandline.ScriptWrapperMain(lambda _: main)
