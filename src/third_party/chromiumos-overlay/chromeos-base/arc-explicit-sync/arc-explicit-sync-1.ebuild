# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

inherit arc-build-constants

DESCRIPTION="Disable explicit sync protocol in Wayland for ARC++"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE="arcpp"
S="${WORKDIR}"

# Block the outdated packages.
RDEPEND="
	!chromeos-base/arc-explicit-sync-asurada
	!chromeos-base/arc-explicit-sync-cherry
	!chromeos-base/arc-explicit-sync-corsola
	!chromeos-base/arc-explicit-sync-jacuzzi
	!chromeos-base/arc-explicit-sync-kukui
	!media-libs/rk3399-arc-explicit-sync
"

src_install() {
	# b/137323525, b/154577590, b/175656896, b/184022391:
	# Wayland explicit sync is enabled by default in ARC++
	# (http://ag/10417600), and some chipsets may experience
	# CtsActivityManagerDeviceTestCases failure with that.
	#
	# This disables the explicit sync to avoid the fence timeout issue.
	if use arcpp; then
		arc-build-constants-configure
		insinto "${ARC_CONTAINER_VENDOR_DIR}/etc/init/"
		doins "${FILESDIR}"/arc-explicit-sync.rc
	fi
}
