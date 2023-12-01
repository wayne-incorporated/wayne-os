#!/usr/bin/env python3
# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Linter for *.mojom files."""

import json
import os
import sys


TOP_DIR = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

# Find chromite!
sys.path.insert(0, os.path.join(TOP_DIR, "..", ".."))

# pylint: disable=wrong-import-position
from chromite.lib import commandline
from chromite.lib import constants
from chromite.lib import cros_build_lib
from chromite.lib import git


# pylint: enable=wrong-import-position

CHECK_STABLE_MOJOM_COMPATIBILITY = os.path.join(
    constants.SOURCE_ROOT,
    "src",
    "platform",
    "libchrome",
    "mojo",
    "public",
    "tools",
    "mojom",
    "check_stable_mojom_compatibility.py",
)


def GetDiffFiles(from_commit, to_commit):
    """Returns the changed file list."""
    cmd = ["diff", "--name-only", from_commit, to_commit]
    res = git.RunGit(TOP_DIR, cmd)
    return res.stdout.splitlines()


def GetRenameMap(from_commit, to_commit):
    """Returns a new name to old name mapping for renamed files."""
    cmd = ["diff", "--name-status", "--diff-filter=R", from_commit, to_commit]
    res = git.RunGit(TOP_DIR, cmd)
    rename_map = {}
    for line in res.stdout.splitlines():
        tokens = line.split("\t")
        rename_map[tokens[2]] = tokens[1]
    return rename_map


def GetFileContent(commit, file):
    """Returns the content of a file in a commit."""
    cmd = ["show", f"{commit}:{file}"]
    res = git.RunGit(TOP_DIR, cmd, check=False)
    return "" if res.returncode else res.stdout


def CheckMojoStable(commit):
    """Checks if the mojom files follow the stable rules."""
    last_commit = f"{commit}^"
    rename_map = GetRenameMap(last_commit, commit)
    delta = []
    for file in GetDiffFiles(last_commit, commit):
        if not file.endswith(".mojom"):
            continue
        old_file = rename_map.get(file, file)
        old_file_content = GetFileContent(last_commit, old_file)
        new_file_content = GetFileContent(commit, file)
        if old_file != file:
            delta += [
                {
                    "filename": old_file,
                    "old": old_file_content,
                    "new": None,
                },
                {
                    "filename": file,
                    "old": None,
                    "new": new_file_content,
                },
            ]
        else:
            delta.append(
                {
                    "filename": file,
                    "old": old_file_content,
                    "new": new_file_content,
                }
            )
    cmd = [CHECK_STABLE_MOJOM_COMPATIBILITY, "--src-root", TOP_DIR]
    res = cros_build_lib.run(cmd, input=json.dumps(delta), check=False)
    if res.returncode:
        cros_build_lib.Die("Please fix the mojom error.")


def GetParser():
    """Returns an argument parser."""
    parser = commandline.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--commit",
        required=True,
        help="The git commit to be checked. "
        'Pass "pre-submit" for the pre-submit check.',
    )
    return parser


def main(argv):
    parser = GetParser()
    opts = parser.parse_args(argv)
    opts.Freeze()

    # If we are running a pre-submit check, check the HEAD.
    commit = opts.commit if opts.commit != "pre-submit" else "HEAD"
    return CheckMojoStable(commit)


if __name__ == "__main__":
    commandline.ScriptWrapperMain(lambda _: main)
