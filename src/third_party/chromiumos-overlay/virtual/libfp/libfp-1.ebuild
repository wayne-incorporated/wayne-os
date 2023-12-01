# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

DESCRIPTION="Virtual for fingerprint support libraries"
SRC_URI=""

LICENSE="metapackage"
SLOT="0"
KEYWORDS="*"

# FP support is board-specific at the moment, this virtual package is here to
# be overriden by overlay virtuals. No dependencies required, they will be in
# the board overlays.
RDEPEND=""
DEPEND=""
