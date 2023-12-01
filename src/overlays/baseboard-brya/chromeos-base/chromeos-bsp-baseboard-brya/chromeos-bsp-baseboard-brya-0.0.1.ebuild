# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

DESCRIPTION="Ebuild which pulls in any necessary ebuilds as dependencies
or portage actions."

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="-* amd64 x86"
IUSE="cheets"
S="${WORKDIR}"

# Add dependencies on other ebuilds from within this board overlay
RDEPEND="
"
DEPEND="${RDEPEND}"
