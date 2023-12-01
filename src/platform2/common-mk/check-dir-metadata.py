#!/usr/bin/env python3
# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Linter for various DIR_METADATA files."""

from __future__ import division

import json
import logging
import os
from pathlib import Path
import sys
from typing import Generator, List, Optional


TOP_DIR = Path(__file__).resolve().parent.parent

# Find chromite!
sys.path.insert(0, str(TOP_DIR.parent.parent))

# pylint: disable=wrong-import-position
from chromite.lib import commandline
from chromite.lib import constants
from chromite.lib import cros_build_lib
from chromite.lib import git


# pylint: enable=wrong-import-position


def GetActiveProjects() -> Generator[Path, None, None]:
    """Return the list of active projects."""
    # Look at all the paths (files & dirs) in the top of the git repo.  This way
    # we ignore local directories devs created that aren't actually committed.
    cmd = ["ls-tree", "--name-only", "-z", "HEAD"]
    result = git.RunGit(TOP_DIR, cmd)

    # Split the output on NULs to avoid whitespace/etc... issues.
    paths = result.stdout.split("\0")

    # ls-tree -z will include a trailing NUL on all entries, not just
    # separation, so filter it out if found (in case ls-tree behavior changes on
    # us).
    for path in [Path(x) for x in paths if x]:
        if (TOP_DIR / path).is_dir():
            yield path


# Legacy projects that don't have a DIR_METADATA file.
# Someone should claim them :D.
LEGACYLIST = {
    "avtest_label_detect",
    "bootid-logger",
    "bootstat",
    "cecservice",
    "cfm-dfu-notification",
    "chromeos-common-script",
    "chromeos-dbus-bindings",
    "chromeos-nvt-tcon-updater",
    "codelab",
    "cronista",
    "crosdns",
    "croslog",
    "disk_updater",
    "dlp",
    "dns-proxy",
    "easy-unlock",
    "featured",
    "glib-bridge",
    "goldfishd",
    "hardware_verifier",
    "hiberman",
    "iioservice",
    "image-burner",
    "imageloader",
    "installer",
    "libbrillo",
    "libchromeos-rs",
    "libchromeos-ui",
    "libcontainer",
    "libmems",
    "libpasswordprovider",
    "login_manager",
    "media_capabilities",
    "media_perception",
    "mems_setup",
    "midis",
    "minios",
    "mist",
    "ml_benchmark",
    "modem-utilities",
    "nnapi",
    "oobe_config",
    "os_install_service",
    "p2p",
    "pciguard",
    "perfetto_simple_producer",
    "permission_broker",
    "policy_proto",
    "policy_utils",
    "power_manager",
    "regions",
    "resourced",
    "run_oci",
    "runtime_probe",  # TODO(b/262377381)
    "screen-capture-utils",
    "secanomalyd",
    "secure_erase_file",
    "secure-wipe",
    "sepolicy",
    "sirenia",
    "spaced",
    "st_flash",
    "storage_info",
    "syslog-cat",
    "system-proxy",
    "timberslide",
    "touch_firmware_calibration",
    "trim",
    "typecd",
    "ureadahead-diff",
    "usb_bouncer",
    "verity",
    "virtual_file_provider",
    "wifi-testbed",
}

# Mapping between tracker & component key name.
DIR_MD_COMPONENT_KEY = (
    ("buganizer", "componentId"),
    ("buganizer_public", "componentId"),
    ("monorail", "component"),
)


def CheckSubdirs() -> int:
    """Check the subdir DIR_METADATA files exist.

    Returns:
        0 if no issues are found, 1 otherwise.
    """

    ret = 0
    for proj in GetActiveProjects():
        path = TOP_DIR / proj / "DIR_METADATA"
        if path.exists():
            if str(proj) in LEGACYLIST:
                logging.error(
                    '*** Project "%s" is in no-DIR_METADATA LEGACYLIST, but '
                    "actually has one. Please remove it from %s:LEGACYLIST!",
                    proj,
                    __file__,
                )
                ret = 1
        else:
            if str(proj) not in LEGACYLIST:
                logging.error(
                    '*** Project "%s" needs a DIR_METADATA file; see common-mk/'
                    "DIR_METADATA for an example",
                    proj,
                )
                ret = 1
            continue

        data = path.read_text()
        for i, line in enumerate(data.splitlines(), start=1):
            if line.rstrip() != line:
                logging.error("*** %s:%i: Trim trailing whitespace", path, i)
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

    # Make sure the projects have declared how to route bugs.
    result = cros_build_lib.dbg_run(
        [
            os.path.join(constants.DEPOT_TOOLS_DIR, "dirmd"),
            "read",
            "-form",
            "computed",
        ],
        cwd=TOP_DIR,
        capture_output=True,
        check=True,
    )
    dirmd = json.loads(result.stdout)
    for project, data in dirmd["dirs"].items():
        bug_component_found = False
        for tracker, key in DIR_MD_COMPONENT_KEY:
            if tracker in data:
                if key not in data[tracker]:
                    logging.error(
                        '*** %s: Missing tracker "%s" component "%s"',
                        project,
                        tracker,
                        key,
                    )
                else:
                    bug_component_found = True
        if not bug_component_found:
            logging.error("*** %s: Missing bug component information", project)

    # Make sure the list doesn't get stale itself.
    old_projects = LEGACYLIST - set(x.name for x in GetActiveProjects())
    if old_projects:
        logging.error(
            "*** %s:LEGACYLIST contains old entries %s.  Please remove them.",
            __file__,
            old_projects,
        )
        ret = 1

    return ret


def GetParser() -> commandline.ArgumentParser:
    """Return an argument parser."""
    parser = commandline.ArgumentParser(description=__doc__)
    return parser


def main(argv: List[str]) -> Optional[int]:
    """The main func!"""
    parser = GetParser()
    opts = parser.parse_args(argv)
    opts.Freeze()

    return CheckSubdirs()


if __name__ == "__main__":
    commandline.ScriptWrapperMain(lambda _: main)
