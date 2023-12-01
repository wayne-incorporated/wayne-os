# Copyright 2020 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

inherit appid cros-unibuild

DESCRIPTION="Ebuild which pulls in any necessary ebuilds as dependencies
or portage actions."

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="-* arm64 arm"
IUSE="zephyr_ec asurada-connectivitynext asurada-kernelnext asurada64"
S="${WORKDIR}"

# Add dependencies on other ebuilds from within this board overlay
RDEPEND="
  chromeos-base/chromeos-config
  chromeos-base/chromeos-bsp-baseboard-asurada
"
DEPEND="${RDEPEND}"

src_install() {
	if use zephyr_ec; then
		doappid "{72518E73-3453-4856-90DA-0E9D809323EC}" "CHROMEBOOK"
	elif use asurada-connectivitynext; then
		doappid "{CF9FCFA1-774A-42CB-80FC-AE7EA1D35477}" "CHROMEBOOK"
	elif use asurada-kernelnext; then
		doappid "{32BD59CB-B6E7-426A-8D90-7A9C990959FA}" "CHROMEBOOK"
	elif use asurada64; then
		doappid "{C376B12F-6C0D-449B-9ECD-2D2DC04E917D}" "CHROMEBOOK"
	else
		doappid "{08F65CC8-BCFB-414F-9B49-DAB2996D2E71}" "CHROMEBOOK"
	fi

	# Install audio config
	unibuild_install_files audio-files
}
