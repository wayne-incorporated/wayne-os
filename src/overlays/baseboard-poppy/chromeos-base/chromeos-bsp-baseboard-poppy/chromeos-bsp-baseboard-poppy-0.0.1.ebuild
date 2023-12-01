# Copyright 2016 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=5

DESCRIPTION="Ebuild which pulls in any necessary ebuilds as dependencies
or portage actions."

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="-* amd64 x86"
IUSE=""
S="${WORKDIR}"

# Add dependencies on other ebuilds from within this board overlay
RDEPEND="
"
DEPEND="${RDEPEND}"

src_install() {
  # Install platform specific config files for power_manager.
  insinto "/usr/share/power_manager/board_specific"
  doins "${FILESDIR}"/powerd_prefs/*
}
