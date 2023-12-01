# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

DESCRIPTION="Generic ebuild which satisfies virtual/chromeos-ec-private-files.
This is a direct dependency of chromeos-base/chromeos-ec, and it is overridden
in private overlay to retrieve the private sources for the EC build."
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform/ec/"

LICENSE="metapackage"
SLOT="0"
KEYWORDS="*"
IUSE=""

RDEPEND="chromeos-base/chromeos-ec-private-files-null"
