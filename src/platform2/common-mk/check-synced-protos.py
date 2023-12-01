#!/usr/bin/env python3
# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Ensure files in missive/proto/synced/ are not manually modified.

Files in missive/proto/synced are synced from Chromium via Copybara and should
not be modified manually. Only Copybara is allowed to modify files in this
directory.
"""

import argparse
from pathlib import Path
import sys
from typing import List, Optional


TOP_DIR = Path(__file__).resolve().parent.parent

# Find chromite.
sys.path.insert(0, str(TOP_DIR.parent.parent))

# pylint: disable=wrong-import-position
from chromite.lib import git


def IsAuthorCopybara(commit: str) -> bool:
    """Indicate whether a commit authored by Copybara.

    Returns:
        True if it is authored by Copybara.
    """
    result = git.RunGit(TOP_DIR, ["show", "-s", "--format=%ae", commit, "--"])
    author_email = result.stdout.strip()
    # Copybara always uses the team email address.
    return author_email == "cros-reporting-team@google.com"


def CheckNoSyncedFilesManuallyModified(file_paths: List[str]) -> bool:
    """Check that synced files aren't modified.

    Files in missive/proto/synced are synced from
    Chromium via Copybara and should not be modified manually.

    Args:
        file_paths: Files modified in this commit.

    Returns:
        True if synced files were not modified, False otherwise
    """
    SYNCED_PROTOS_PATH = "missive/proto/synced"

    for path in file_paths:
        if SYNCED_PROTOS_PATH in path:
            print(
                f"{path} changed.\n"
                f"Cannot upload changes to protos in {SYNCED_PROTOS_PATH}.\n"
                "Protos must be synced from the Chromium repo.\n"
                "See chromium/src/components/reporting/proto/synced/README in "
                "the Chromium repo for instructions.",
                file=sys.stderr,
            )
            return False
    return True


def get_parser():
    """Return an argument parser."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--commit", help="Hash of the commit to check in.")
    parser.add_argument("files", nargs="*", help="Files to check.")
    return parser


def main(argv: Optional[List[str]] = None) -> Optional[int]:
    parser = get_parser()
    opts = parser.parse_args(argv)
    # If we are running a pre-submit check, check the HEAD.
    commit = opts.commit if opts.commit != "pre-submit" else "HEAD"
    if IsAuthorCopybara(commit):
        # Don't check if the author is copybara.
        return 0
    return 0 if CheckNoSyncedFilesManuallyModified(opts.files) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
