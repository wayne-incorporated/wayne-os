#!/usr/bin/env python3
# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Wrapper for platform2_test for meson packages.

This mostly sets some environment variables that can't easily be set
in meson.eclass.
"""

import os
from pathlib import Path
import sys


def translate_path(sysroot, path):
    """Remove the SYSROOT prefix from paths that have it"""

    if path.startswith(sysroot):
        return path[len(sysroot) :]
    return path


def append_env_path(real_argv, sysroot, env_name):
    """Translate the path in |env_name| and add it to |real_argv|"""

    if env_name in os.environ:
        translated_path = translate_path(sysroot, os.environ[env_name])
        real_argv += ["--env", f"{env_name}={translated_path}"]


def main(argv):
    DIR = Path(__file__).resolve().parent
    real_argv = [DIR / "platform2_test.py"]

    sysroot = os.environ["SYSROOT"]
    real_argv += ["--sysroot", sysroot]

    # Several meson packages pass the path to the build or source
    # directory into their tests using an environment variable so they
    # can read data files or execute other test programs. These paths
    # will be from the perspective of the cros chroot, not from the
    # build sysroot that the test is actually going to run from. We
    # can translate these paths by just stripping the ${SYSROOT}
    # prefix from the start.
    #
    # Unfortunately there doesn't seem to be any standard approach to
    # this, so we just have to look at all the env variables we have
    # observed being used in this way.

    # Used by dev-libs/wayland
    append_env_path(real_argv, sysroot, "TEST_BUILD_DIR")
    append_env_path(real_argv, sysroot, "TEST_SRC_DIR")

    # Used by media-libs/harfbuzz, dev-libs/json-glib, app-arch/gcab,
    # dev-libs/glib
    append_env_path(real_argv, sysroot, "G_TEST_BUILDDIR")
    append_env_path(real_argv, sysroot, "G_TEST_SRCDIR")

    # Used by x11-libs/libxkbcommon
    append_env_path(real_argv, sysroot, "top_builddir")
    append_env_path(real_argv, sysroot, "top_srcdir")

    real_argv += ["--"]
    real_argv += argv

    print(f"Running {real_argv}", flush=True)
    os.execv(real_argv[0], real_argv)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
