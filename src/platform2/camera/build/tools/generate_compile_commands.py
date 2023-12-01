#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""A tool to generate compile_commands file."""

import argparse
import json
import logging
import os
import re
import subprocess
import sys
from typing import List


PLATFORM2_CAMERA_CORE_PACKAGES = [
    "chromeos-base/cros-camera",
    "chromeos-base/cros-camera-android-deps",
    "chromeos-base/cros-camera-diagnostics",
    "chromeos-base/cros-camera-libs",
    "chromeos-base/cros-camera-tool",
    "media-libs/cros-camera-connector-client",
    "media-libs/cros-camera-frame-annotator",
    "media-libs/cros-camera-hal-usb",
]

PLATFORM2_CAMERA_TEST_PACKAGES = [
    # 'media-libs/cros-camera-libjda_test',  # not buildable at the moment
    "media-libs/cros-camera-gpu-test",
    "media-libs/cros-camera-hdrnet-tests",
    "media-libs/cros-camera-libjea_test",
    "media-libs/cros-camera-test",
    "media-libs/cros-camera-usb-tests",
]

SYSROOT_COMPILEDB_PATH = "/build/{board}/build/compilation_database/{pkg}"
COMPILE_COMMANDS_CHROOT = "compile_commands_chroot.json"
COMPILE_COMMANDS_NO_CHROOT = "compile_commands_no_chroot.json"


def get_canonical_package_name(board: str, pkg: str) -> str:
    cmd = [f"equery-{board}", "which", pkg]
    try:
        output = subprocess.run(
            cmd, check=True, encoding="utf-8", stdout=subprocess.PIPE
        )
    except subprocess.CalledProcessError:
        raise ValueError(f"Unknown package: {pkg}")
    ebuild_package_path = os.path.dirname(output.stdout.strip())
    pkg_name = os.path.basename(ebuild_package_path)
    pkg_category = os.path.basename(os.path.dirname(ebuild_package_path))
    return "/".join((pkg_category, pkg_name))


def fix_source_file_path(compdb: List[dict], chroot: bool):
    """Fix file paths.

    This is required for platform2 packages that are not being cros-workon
    started, or for packages in platform/camera.
    """

    patterns = {
        # For src/platform/camera
        r"platform2/camera_hal/(.*)": "src/platform/camera",
        # For repos in src/platform2
        r"platform2/(.*)": "src/plaform2",
    }

    KEY_FILE = "file"
    for cmd in compdb:
        if KEY_FILE not in cmd:
            continue
        filepath = cmd[KEY_FILE]
        if filepath.startswith("gen/"):
            continue

        match_obj = None
        repo_path = None
        for k, v in patterns.items():
            match_obj = re.search(k, filepath)
            if match_obj:
                repo_path = v
                break
        if not match_obj or not repo_path:
            logging.debug("Unrecognized source file %s", filepath)
            continue

        if chroot:
            src_root = "/mnt/host/source"
        else:
            src_root = os.environ.get("EXTERNAL_TRUNK_PATH")
            assert src_root is not None
        cmd[KEY_FILE] = os.path.join(src_root, repo_path, match_obj.group(1))


def fix_include_path(compdb: List[dict], chroot: bool):
    """Fix the -I include paths in cflags.

    This is required for packages in platform/camera, but nice-to-have for
    platform2 packages.
    """

    patterns = {
        # For src/platform/camera
        r"-I[^ ]*/platform2/camera_hal/([^ ]*)": "src/platform/camera",
        # For repos in src/platform2
        r"-I[^ ]*/platform2/?([^ ]*)": "src/platform2",
    }

    KEY_COMMAND = "command"
    for cmd in compdb:
        if KEY_COMMAND not in cmd:
            continue

        if chroot:
            src_root = "/mnt/host/source"
        else:
            src_root = os.environ.get("EXTERNAL_TRUNK_PATH")
            assert src_root is not None

        for k, v in patterns.items():
            cmd[KEY_COMMAND] = re.sub(
                k,
                "-I%s/%s" % (os.path.join(src_root, v), r"\1"),
                cmd[KEY_COMMAND],
            )


def emerge_packages(board: str, packages: List[str], use_flags: str):
    """Run emerge command to build the packages."""

    flags = "compilation_database"
    if use_flags:
        flags = " ".join([flags, use_flags])
    logging.info(
        "Emerging the following packages with USE flags (%s):\n\t%s",
        flags,
        "\n\t".join(packages),
    )
    emerge_env = os.environ
    emerge_env["USE"] = flags
    emerge_cmd = [f"emerge-{board}", "-j", *packages]
    logging.debug("Running emerge cmd: %s with env: %s", emerge_cmd, emerge_env)
    subprocess.run(emerge_cmd, env=emerge_env, check=True)


def aggregate_compile_db(
    board: str, packages: List[str], chroot: bool
) -> List[dict]:
    """Aggregate the compilation database of the given packages into a list."""

    compdb_files = []
    for p in packages:
        compdb_path = os.path.join(
            SYSROOT_COMPILEDB_PATH.format(board=board, pkg=p),
            COMPILE_COMMANDS_CHROOT if chroot else COMPILE_COMMANDS_NO_CHROOT,
        )
        if os.path.exists(compdb_path):
            compdb_files.append(compdb_path)

    logging.info(
        "Combining the following compilation database:\n\t%s",
        "\n\t".join(compdb_files),
    )
    result = []
    for path in compdb_files:
        # pylint: disable=encoding-missing
        with open(path, "r", encoding="utf-8") as f:
            result.extend(json.loads(f.read()))
    return result


def auto_cros_workon_packages(board: str, packages: List[str]):
    """Temporarily cros-workon start on the given packages.

    This is to produce compilation database with usable paths inside the code
    repo. Without cros-workon start, the include and source code paths would
    point to the temporary workdir generated by portage.

    Returns a clean-up closure function for the caller to restore the
    cros-workon state.
    """

    cros_workon_cmd = f"cros-workon-{board}"
    list_cmd = [cros_workon_cmd, "list"]
    try:
        output = subprocess.run(
            list_cmd, check=True, encoding="utf-8", stdout=subprocess.PIPE
        )
    except subprocess.CalledProcessError:
        raise ValueError(f"Cannot get cros-workon list for board {board}")

    already_workon_packages = set(output.stdout.splitlines())
    logging.debug(
        "Board %s is already working on packages: %s",
        board,
        already_workon_packages,
    )
    temp_workon_packages = set(packages) - already_workon_packages
    logging.info(
        (
            "Will temporarily cros-workon-start on the "
            "following packages:\n\t%s"
        ),
        "\n\t".join(temp_workon_packages),
    )

    start_cmd = [cros_workon_cmd, "start", *temp_workon_packages]
    try:
        subprocess.run(start_cmd, check=True)
    except subprocess.CalledProcessError:
        raise ValueError(f"Cannot cros-workon start for board {board}")

    return lambda: subprocess.run(
        [cros_workon_cmd, "stop", *temp_workon_packages], check=True
    )


def main(argv: list):
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-b",
        "--board",
        type=str,
        required=True,
        help=(
            "The board to emerge the camera packages for and copy the "
            "compilation database from"
        ),
    )
    parser.add_argument(
        "-o",
        "--output_file",
        type=str,
        default="compile_commands.json",
        help=("Output compilation database file name (default=%(default)s)"),
    )
    parser.add_argument(
        "--noemerge",
        dest="emerge",
        action="store_false",
        default=True,
        help=(
            "Do not emerge the packages and combine the available existing "
            "compilation database in the sysroot"
        ),
    )
    parser.add_argument(
        "--chroot",
        dest="chroot",
        action="store_true",
        default=False,
        help=("Generate the chroot version of compilation database"),
    )
    parser.add_argument(
        "--append",
        action="store_true",
        help=(
            "Append the compilation database of the specified package to the "
            "existing compdb file instead of overwritting it"
        ),
    )
    parser.add_argument(
        "--debug", action="store_true", help="Enable debug logs"
    )
    parser.add_argument(
        "--use",
        type=str,
        default="",
        help=(
            "Additional USE flag(s) to enable when emerging the packages, e.g. "
            '"test -asan"'
        ),
    )
    parser.add_argument(
        "--noauto-cros-workon-start",
        dest="auto_cros_workon_start",
        action="store_false",
        default=True,
        help=("Automatically cros-workon-start the packages"),
    )
    parser.add_argument(
        "packages",
        type=str,
        nargs="*",
        # pylint: disable=consider-using-f-string
        help=(
            "Package(s) to emerge and/or copy compilation database from, in "
            "addition to the default set of packages: %s"
            % " ".join(
                PLATFORM2_CAMERA_CORE_PACKAGES + PLATFORM2_CAMERA_TEST_PACKAGES
            )
        ),
    )
    args = parser.parse_args(argv)

    log_level = logging.INFO
    if args.debug:
        log_level = logging.DEBUG
    logging.basicConfig(level=log_level)

    if not os.path.exists("/etc/cros_chroot_version"):
        raise RuntimeError("The script needs to run inside the CrOS SDK chroot")

    all_packages = (
        PLATFORM2_CAMERA_CORE_PACKAGES
        + PLATFORM2_CAMERA_TEST_PACKAGES
        + [get_canonical_package_name(args.board, p) for p in args.packages]
    )
    cleanup_closure = None

    try:
        if args.auto_cros_workon_start:
            cleanup_closure = auto_cros_workon_packages(
                args.board, all_packages
            )

        if args.emerge:
            emerge_packages(args.board, all_packages, args.use)

        compdb_aggregated = []
        if args.append and os.path.exists(args.output_file):
            logging.info(
                "Append to the existing compdb file %s", args.output_file
            )
            # pylint: disable=encoding-missing
            with open(args.output_file, "r", encoding="utf-8") as f:
                compdb_aggregated.extend(json.loads(f.read()))

        compdb_aggregated.extend(
            aggregate_compile_db(args.board, all_packages, args.chroot)
        )

        fix_source_file_path(compdb_aggregated, args.chroot)
        fix_include_path(compdb_aggregated, args.chroot)

        # pylint: disable=encoding-missing
        with open(args.output_file, "w+", encoding="utf-8") as f:
            f.write(json.dumps(compdb_aggregated, indent=2))
    finally:
        if cleanup_closure is not None:
            cleanup_closure()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
