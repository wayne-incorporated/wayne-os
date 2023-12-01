# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=5

inherit appid

DESCRIPTION="Ebuild which pulls in any necessary ebuilds as dependencies
or portage actions."

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="-* amd64 x86"
IUSE="kernel-4_14"
S="${WORKDIR}"

# Add dependencies on other ebuilds from within this board overlay
RDEPEND="
	kernel-4_14?  ( chromeos-base/sof-binary chromeos-base/sof-topology )
	!kernel-4_14? ( sys-firmware/sof-firmware )
	chromeos-base/chromeos-disk-firmware-baseboard-octopus
"
DEPEND="${RDEPEND}"
