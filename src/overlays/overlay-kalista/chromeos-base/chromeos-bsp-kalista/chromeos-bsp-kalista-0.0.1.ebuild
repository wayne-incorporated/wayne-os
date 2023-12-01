# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=5

inherit appid cros-unibuild udev

DESCRIPTION="Ebuild which pulls in any necessary ebuilds as dependencies
or portage actions."

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="-* amd64 x86"
IUSE="kalista-cfm kalista-kernelnext"
S="${WORKDIR}"

# Add dependencies on other ebuilds from within this board overlay
RDEPEND="chromeos-base/chromeos-config"
DEPEND="${RDEPEND}"

src_install() {
	if use kalista-cfm; then
		doappid "{AE78E4C6-CF2D-411C-AB9A-339904DE5E2B}" "CHROMEBASE"
	elif use kalista-kernelnext; then
		doappid "{786976FC-8386-45D6-B955-6D01C1BE131D}" "CHROMEBASE"
	else
		doappid "{073ABAF9-40D3-4065-85F3-74B1FA49675D}" "CHROMEBASE"
	fi

	unibuild_install_files audio-files

	# Install udev rules
	udev_dorules "${FILESDIR}"/udev/*.rules
}
