#!/bin/bash

# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Script to build a bootable keyfob-based chromeos system image from within
# a chromiumos setup. This assumes that all needed packages have been built into
# the given target's root with binary packages turned on. This script will
# build the Chrome OS image using only pre-built binary packages.

SCRIPT_ROOT="$(dirname "$(readlink -f "$0")")"
# shellcheck source=build_library/build_common.sh
. "${SCRIPT_ROOT}/build_library/build_common.sh" || exit 1

if [[ "$1" != "--script-is-run-only-by-chromite-and-not-users" ]]; then
  die_notrace 'This script must not be run by users.' \
    'Please run `build_images` from $PATH (in chromite/bin/) instead.'
fi

# Discard the 'script-is-run-only-by-chromite-and-not-users' flag.
shift

# Developer-visible flags.
DEFINE_string adjust_part "" \
  "Adjustments to apply to partition table (LABEL:[+-=]SIZE) e.g. ROOT-A:+1G"
DEFINE_string board "${DEFAULT_BOARD}" \
  "The board to build an image for."
DEFINE_string boot_args "noinitrd" \
  "Additional boot arguments to pass to the commandline"
DEFINE_boolean enable_bootcache ${FLAGS_FALSE} \
  "Default all bootloaders to NOT use boot cache."
DEFINE_boolean enable_rootfs_verification ${FLAGS_TRUE} \
  "Default all bootloaders to use kernel-based root fs integrity checking." \
  r
DEFINE_string disk_layout "default" \
  "The disk layout type to use for this image."
DEFINE_string enable_serial "" \
  "Enable serial port for printks. Example values: ttyS0"
DEFINE_integer loglevel 7 \
  "The loglevel to add to the kernel command line."
DEFINE_string builder_path "" \
  "The build_name to be installed on DUT during hwtest."


FLAGS_HELP="USAGE: build_image [flags] [list of images to build].
This script is used to build a Chromium OS image. Chromium OS comes in many
different forms.  This scripts can be used to build the following:

base - Pristine Chromium OS image. As similar to Chrome OS as possible.
dev [default] - Developer image. Like base but with additional dev packages.
test - Like dev, but with additional test specific packages and can be easily
  used for automated testing using scripts like test_that, etc.
factory_install - Install shim for bootstrapping the factory test process.
  Cannot be built along with any other image.

Examples:

build_image --board=<board> dev test - builds developer and test images.
build_image --board=<board> factory_install - builds a factory install shim.

Note if you want to build an image with custom size partitions, either consider
adding a new disk layout in build_library/legacy_disk_layout.json OR use
adjust_part. See the help above but here are a few examples:

adjust_part='STATE:+1G' -- add one GB to the size the stateful partition
adjust_part='ROOT-A:-1G' -- remove one GB from the primary rootfs partition
adjust_part='STATE:=1G' --  make the stateful partition 1 GB
...
"

# The following options are advanced options, only available to those willing
# to read the source code. They are not shown in help output, since they are
# not needed for the typical developer workflow.
DEFINE_integer jobs -1 \
  "How many packages to build in parallel at maximum."

# Parse command line.
FLAGS "$@" || exit 1

eval set -- "${FLAGS_ARGV}"

# Only now can we die on error. shflags functions leak non-zero error codes,
# so will die prematurely if 'switch_to_strict_mode' is specified before now.
switch_to_strict_mode

# N.B.  Ordering matters for some of the libraries below, because
# some of the files contain initialization used by later files.
# shellcheck source=build_library/board_options.sh
. "${BUILD_LIBRARY_DIR}/board_options.sh" || exit 1
# shellcheck source=build_library/disk_layout_util.sh
. "${BUILD_LIBRARY_DIR}/disk_layout_util.sh" || exit 1
# shellcheck source=build_library/mount_gpt_util.sh
. "${BUILD_LIBRARY_DIR}/mount_gpt_util.sh" || exit 1
# shellcheck source=build_library/build_image_util.sh
. "${BUILD_LIBRARY_DIR}/build_image_util.sh" || exit 1
# shellcheck source=build_library/base_image_util.sh
. "${BUILD_LIBRARY_DIR}/base_image_util.sh" || exit 1
# shellcheck source=build_library/dev_image_util.sh
. "${BUILD_LIBRARY_DIR}/dev_image_util.sh" || exit 1
# shellcheck source=build_library/test_image_util.sh
. "${BUILD_LIBRARY_DIR}/test_image_util.sh" || exit 1
# shellcheck source=build_library/selinux_util.sh
. "${BUILD_LIBRARY_DIR}/selinux_util.sh" || exit 1

IMAGES_TO_BUILD="$*"

load_board_specific_script "board_specific_setup.sh"

# TODO: <prebuild hook>

# Create the base image.
create_base_image "${PRISTINE_IMAGE_NAME}" \
  "${FLAGS_enable_rootfs_verification}" "${FLAGS_enable_bootcache}"

# Running board-specific setup if any exists.
if type board_setup &>/dev/null; then
  board_setup "${BUILD_DIR}/${PRISTINE_IMAGE_NAME}"
fi

# Create a developer image if an image that is based on it is requested.
if should_build_image "${CHROMEOS_DEVELOPER_IMAGE_NAME}" \
    "${CHROMEOS_TEST_IMAGE_NAME}"; then
  copy_image "${CHROMEOS_BASE_IMAGE_NAME}" "${CHROMEOS_DEVELOPER_IMAGE_NAME}"
  install_dev_packages "${CHROMEOS_DEVELOPER_IMAGE_NAME}"
fi

# From a developer image create a test image.
if should_build_image "${CHROMEOS_TEST_IMAGE_NAME}"; then
  copy_image  "${CHROMEOS_DEVELOPER_IMAGE_NAME}" "${CHROMEOS_TEST_IMAGE_NAME}"
  mod_image_for_test  "${CHROMEOS_TEST_IMAGE_NAME}"
fi
