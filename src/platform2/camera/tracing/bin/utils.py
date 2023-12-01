# -*- coding: utf-8 -*-

# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Common utilities."""

import logging
import os
import re
import shlex
from typing import Optional


def wrap_cmd(cmd: list, remote: Optional[str]) -> list:
    """Helper function to quote args when needed."""
    ret = cmd
    if remote:
        ret = ["ssh", remote] + [shlex.quote(c) for c in cmd]
    logging.debug("Command: %s", ret)
    return ret


def is_inside_chroot() -> bool:
    return os.environ.get("CROS_WORKON_SRCROOT") is not None


def is_on_dut() -> bool:
    try:
        with open("/etc/lsb-release") as f:
            return (
                re.search(r"CHROMEOS_RELEASE_BOARD", f.read(), re.MULTILINE)
                is not None
            )
    except FileNotFoundError:
        return False


def get_repo_file_path(path: str) -> str:
    if os.path.isabs(path):
        return path

    src_root = os.environ.get("CROS_WORKON_SRCROOT")
    if src_root:
        # In CrOS SDK chroot.
        return os.path.join(src_root, path)

    # This assume that __file__ resides in src/platform2/camera/tracing/bin
    assert os.path.dirname(__file__).endswith(
        "src/platform2/camera/tracing/bin"
    )
    repo_base_dir = os.path.realpath(
        os.path.join(
            os.path.dirname(__file__),
            "..",
            "..",
            "..",
            "..",
            "..",
        )
    )
    return os.path.join(repo_base_dir, path)
