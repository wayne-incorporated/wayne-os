# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=5

inherit appid cros-unibuild udev

DESCRIPTION="Ebuild which pulls in any necessary ebuilds as dependencies
or portage actions."

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="-* arm64 arm"
IUSE="kukui-arc-r kukui-tablet kukui-kernelnext"
S="${WORKDIR}"

# Add dependencies on other ebuilds from within this board overlay
RDEPEND="
	chromeos-base/chromeos-config
	chromeos-base/chromeos-bsp-baseboard-kukui
"
DEPEND="${RDEPEND}"

src_install() {
	if use kukui-arc-r; then
		doappid "{D67CDE4D-0AA7-4550-BCBC-B43F61F2966E}" "CHROMEBOOK"
	elif use kukui-tablet; then
		doappid "{8748A652-A3D9-4EA6-9E3D-4B97795DBF5B}" "CHROMEBOOK"
	elif use kukui-kernelnext; then
		doappid "{58840B5E-8164-11EB-8633-DBDBCDFF2C4B}" "CHROMEBOOK"
	else
		doappid "{50F3C95B-CA5B-4AF8-87A2-8CD19588BD12}" "CHROMEBOOK"
	fi

	# Install a rule tagging keyboard as internal
	udev_dorules "${FILESDIR}/91-hammer-keyboard.rules"

	# Install hammerd udev rules and override for chromeos-base/hammerd.
	udev_dorules "${FILESDIR}/99-hammerd.rules"

	# Install audio config
	unibuild_install_files audio-files

	# In the krane device, we separate the 0E30 to two different PIDs
	# after the board_rev>=5. To backward compatible with the old devices,
	# we query the sensor id and use it as the indicator to override the
	# active_product_id to force the touch updater use the new PID.
	exeinto "/opt/google/touch/scripts"
	doexe "${FILESDIR}"/get_board_goodix_pid.sh

	# Install platform-specific bluetooth sysprops.
	insinto "/etc/bluetooth/sysprops.conf.d"
	insopts -m0640
	doins "${FILESDIR}/kukui-bluetooth-sysprops.conf"
	insopts -m0644
}
