#!/bin/sh

# Copyright 2011 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# ChromeOS version information
#
# This file is usually sourced by other build scripts, but can be run
# directly to see what it would do.

#############################################################################
# SET VERSION NUMBERS
#############################################################################
# Release Build number.
# Increment by 1 for every release build.
CHROMEOS_BUILD=15509

# Release Branch number.
# Increment by 1 for every release build on a branch.
# Reset to 0 when increasing release build number.
CHROMEOS_BRANCH=81

# Patch number.
# Increment by 1 in case a non-scheduled branch release build is necessary.
# Reset to 0 when increasing branch number.
CHROMEOS_PATCH=0

# Version string. Not indentied to appease bash.
# Suppress unused var warning. This variable is used in show_vars().
# shellcheck disable=SC2034
CHROMEOS_VERSION_STRING=\
"${CHROMEOS_BUILD}.${CHROMEOS_BRANCH}.${CHROMEOS_PATCH}"

# Major version for Chrome.
# shellcheck disable=SC2034
CHROME_BRANCH=116
# Set CHROME values (Used for releases) to pass to chromeos-chrome-bin ebuild
# URL to chrome archive
# shellcheck disable=SC2034
CHROME_BASE=
# Set CHROME_VERSION from incoming value or NULL and let ebuild default.
: "${CHROME_VERSION:=}"

# Print (and remember) version info.  We do each one by hand because there might
# be more/other vars in the env already that start with CHROME_ or CHROMEOS_.
echo "Chromium OS version information:"
(
# Subshell to hide the show_vars definition.
show_vars() {
  local v
  for v in "$@"; do
    eval echo \""    ${v}=\${${v}}"\"
  done
}
show_vars \
  CHROME_BASE \
  CHROME_BRANCH \
  CHROME_VERSION \
  CHROMEOS_BUILD \
  CHROMEOS_BRANCH \
  CHROMEOS_PATCH \
  CHROMEOS_VERSION_STRING
)
