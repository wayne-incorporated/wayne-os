# Copyright 2014 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

DESCRIPTION="List of packages that are needed inside the sdk to build everything;
by default, we build a Chromium OS SDK"
HOMEPAGE="http://dev.chromium.org/"

LICENSE="metapackage"
SLOT="0"
KEYWORDS="*"
IUSE=""

RDEPEND="virtual/target-chromium-os-sdk"
DEPEND="${RDEPEND}"
