# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

DESCRIPTION="Generic ebuild which satisfies virtual/chromeos-ec-touch-firmware.
This is a direct dependency of chromeos-base/chromeos-ec, and can be overridden
in an overlay for each specialized board, if a touch FW needs to be provided
to the EC build system at compile time (e.g. to generate hashes to be included
in RW section)."
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform/ec/"

LICENSE="metapackage"
SLOT="0"
KEYWORDS="*"
IUSE=""

RDEPEND=""
DEPEND="${RDEPEND}"
