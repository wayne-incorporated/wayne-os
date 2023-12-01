# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=5

inherit udev

DESCRIPTION="Scripts for setting up HDCP keys for devices where it's in VPD"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE="-rk32 -rk3399"
REQUIRED_USE="|| ( rk32 rk3399 )"

S="${WORKDIR}"

src_install() {
	use rk32 && udev_dorules \
		"${FILESDIR}"/udev/rules.d/99-rk3288-hdcp.rules
	use rk3399 && udev_dorules \
		"${FILESDIR}"/udev/rules.d/99-rk3399-hdcp.rules

	# Install device specific HDCP script
	exeinto "$(get_udevdir)"
	doexe "${FILESDIR}/hdcp_pass_key.sh"
}
