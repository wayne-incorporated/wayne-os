# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

# @ECLASS: libchrome-version.eclass
# @MAINTAINER:
# ChromiumOS Build Team
# @BUGREPORTS:
# Please report bugs via http://crbug.com/new (with label Build)
# @VCSURL: https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/HEAD/eclass/@ECLASS@
# @BLURB: helper eclass for managing libchrome version
# @DESCRIPTION:
# This eclass manages the libchrome ebuild version.
# This file is also owned by libchrome team in case of revision bump.
# Prefer updating the REQUIRED version number in this file (as opposed to adding
# ">=" dependencies on libchrome or libbrillo to other packages ebuild files).

# shellcheck disable=SC2034
REQUIRED_LIBCHROME_EBUILD_VERSION=711
REQUIRED_LIBBRILLO_EBUILD_VERSION=2220
