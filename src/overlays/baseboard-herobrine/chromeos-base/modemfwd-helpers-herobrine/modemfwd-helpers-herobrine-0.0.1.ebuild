# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

inherit cros-cellular

DESCRIPTION="Chrome OS Modem Update Helpers (herobrine)"
HOMEPAGE="http://src.chromium.org"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE="internal"

S="${WORKDIR}"
DEPEND="
internal? (	chromeos-base/modem-fw-dlc-piglin
		chromeos-base/modem-fw-dlc-herobrine
		chromeos-base/modem-fw-dlc-hoglin
		chromeos-base/modem-fw-dlc-zoglin
		chromeos-base/modem-fw-dlc-evoker
		chromeos-base/modem-fw-dlc-zombie
		chromeos-base/modem-fw-dlc-villager )
chromeos-base/qc-modemfwd-helper
"
RDEPEND="${DEPEND}"

src_install() {
	cellular_domanifest "${FILESDIR}/helper_manifest.prototxt"

	insinto /etc/init/
	doins "${FILESDIR}/modemfwd-helpers.conf"
	doins "${FILESDIR}/modemfwd-check.conf"

	cellular_dofirmware "${FILESDIR}/firmware_manifest.prototxt"

	# fw is currently loaded to the image using src/private-overlays/baseboard-herobrine-private/chromeos-base/sc7280-modem-firmware/
	# chromeos-base/modem-fw-dlc-villager reserves space for DLC's until DLCs can be enabled.
}
