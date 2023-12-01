# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=6

# This ebuild only cares about its own FILESDIR and ebuild file, so it tracks
# the canonical empty project.
CROS_WORKON_COMMIT="d2d95e8af89939f893b1443135497c1f5572aebc"
CROS_WORKON_TREE="776139a53bc86333de8672a51ed7879e75909ac9"
CROS_WORKON_PROJECT="chromiumos/infra/build/empty-project"
CROS_WORKON_LOCALNAME="platform/empty-project"

inherit appid
inherit cros-unibuild
inherit cros-workon
inherit udev

DESCRIPTION="Ebuild which pulls in any necessary ebuilds as dependencies
or portage actions."

LICENSE="BSD-Google"
KEYWORDS="-* amd64 x86"
IUSE="zork-arc-r zork-borealis zork-kernelnext zork-connectivitynext modemfwd"

# Add dependencies on other ebuilds from within this board overlay
RDEPEND="
	!<chromeos-base/gestures-conf-0.0.2
	chromeos-base/rmi4utils:=
	chromeos-base/touch_updater:=
	modemfwd? ( chromeos-base/modemfwd-helpers )
"
DEPEND="
	${RDEPEND}
	chromeos-base/chromeos-config:=
"

src_install() {
	insinto "/etc/gesture"
	doins "${FILESDIR}"/gesture/*

	if use zork-arc-r; then
		doappid "{63ADFE60-D637-416A-A595-E5BA72D185FF}" "CHROMEBOOK"
	elif use zork-borealis; then
		doappid "{06A95C4E-E191-11EA-A4BD-770DFD0DD974}" "CHROMEBOOK"
	elif use zork-connectivitynext; then
		doappid "{AD30E25F-9915-480B-B00D-2D8F5D87FE16}" "CHROMEBOOK"
	elif use zork-kernelnext; then
		doappid "{D694EA84-A2C3-11EA-98E4-DFA8D65B1A07}" "CHROMEBOOK"
	else
		doappid "{0BE68F68-A2F2-46B7-A7B4-B51B63F64FBA}" "CHROMEBOOK"
	fi

	unibuild_install_files audio-files

	# Install LTE modem quirks
	exeinto /usr/sbin
	doexe "${FILESDIR}/modem_startup"
	doexe "${FILESDIR}/modem_shutdown"

	# Install USB quirks
	udev_dorules "${FILESDIR}/20-usb-quirks.rules"
	udev_dorules "${FILESDIR}/90-xhci-quirks.rules"

	# Install Proximity sensor rules
	udev_dorules "${FILESDIR}"/vilboz/udev/*.rules

	exeinto "$(get_udevdir)"
	doexe "${FILESDIR}/xhci-restart.sh"
}
