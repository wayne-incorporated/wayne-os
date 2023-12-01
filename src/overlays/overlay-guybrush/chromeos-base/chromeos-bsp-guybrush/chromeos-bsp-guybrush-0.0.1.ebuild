# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=6

inherit appid cros-unibuild udev


DESCRIPTION="Ebuild which pulls in any necessary ebuilds as dependencies
or portage actions."

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="-* amd64 x86"
S="${WORKDIR}"
IUSE="guybrush-arc-t guybrush-kernelnext"

# Add dependencies on other ebuilds from within this board overlay
RDEPEND="
	chromeos-base/sof-binary
	chromeos-base/sof-topology
"
DEPEND="
	${RDEPEND}
	chromeos-base/chromeos-config
"

src_install() {
	if use guybrush-arc-t; then
		doappid "{62B84D24-99F9-4A42-A179-567347BFDD0A}" "CHROMEBOOK"
	elif use guybrush-kernelnext; then
		doappid "{39ECC3D3-D4FC-4977-A3A1-9C5859E55AE5}" "CHROMEBOOK"
	else
		doappid "{BAEFD150-0AC7-4FC9-A044-8C3F317F7CD9}" "REFERENCE"
	fi

	unibuild_install_files audio-files

	# Install USB quirks
	udev_dorules "${FILESDIR}/common/20-usb-quirks.rules"
}
