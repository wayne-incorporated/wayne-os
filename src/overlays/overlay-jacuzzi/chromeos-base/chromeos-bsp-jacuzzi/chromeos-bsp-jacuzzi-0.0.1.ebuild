# Copyright 2019 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=6

inherit appid cros-unibuild

DESCRIPTION="Ebuild which pulls in any necessary ebuilds as dependencies
or portage actions."

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="-* arm64 arm"
IUSE="jacuzzi-kernelnext"
S="${WORKDIR}"

# Add dependencies on other ebuilds from within this board overlay
RDEPEND="
	!<chromeos-base/gestures-conf-0.0.2
	chromeos-base/chromeos-bsp-baseboard-kukui
	chromeos-base/chromeos-config
"
DEPEND="${RDEPEND}"

src_install() {
	insinto "/etc/gesture"
	doins "${FILESDIR}"/gesture/*

	if use jacuzzi-kernelnext; then
		doappid "{94AE1860-91C5-11EB-BAEA-C76F2B34FA33}" "CHROMEBOOK"
	else
		doappid "{BA7092E6-2B09-4620-BBB0-FAA34397F3F8}" "CHROMEBOOK"
	fi

	# Install audio config
	unibuild_install_files audio-files

	# Install platform-specific bluetooth sysprops.
	insinto "/etc/bluetooth/sysprops.conf.d"
	insopts -m0640
	doins "${FILESDIR}/common/jacuzzi-bluetooth-sysprops.conf"
	insopts -m0644
}
