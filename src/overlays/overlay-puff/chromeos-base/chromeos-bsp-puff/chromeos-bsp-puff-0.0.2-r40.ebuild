# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

# This ebuild only cares about its own FILESDIR and ebuild file, so it tracks
# the canonical empty project.
CROS_WORKON_COMMIT="d2d95e8af89939f893b1443135497c1f5572aebc"
CROS_WORKON_TREE="776139a53bc86333de8672a51ed7879e75909ac9"
CROS_WORKON_PROJECT="chromiumos/infra/build/empty-project"
CROS_WORKON_LOCALNAME="platform/empty-project"

inherit appid cros-unibuild cros-workon udev

DESCRIPTION="Ebuild which pulls in any necessary ebuilds as dependencies
or portage actions."

LICENSE="BSD-Google"
KEYWORDS="-* amd64 x86"
IUSE="iioservice puff-borealis puff-kernelnext kernel-4_19"

# Add dependencies on other ebuilds from within this board overlay
RDEPEND="
	kernel-4_19? ( chromeos-base/sof-binary:= chromeos-base/sof-topology:= )
	!kernel-4_19? ( sys-firmware/sof-firmware:= )
	chromeos-base/touch_updater:=
"
DEPEND="
	${RDEPEND}
	chromeos-base/chromeos-config:=
"

src_install() {
	if use puff-borealis; then
		doappid "{95056F9C-22C7-11EB-91D7-FFB4065ABAAB}" "CHROMEBOX"
	elif use puff-kernelnext; then
		doappid "{D9966676-6FA6-4608-B2C5-DBAC1559B7EC}" "CHROMEBOX"
	else
		doappid "{2514829E-8550-4E24-91F2-331AB7A12B03}" "CHROMEBOX"
	fi

	# Monitor udev event for USB ports to control power of re-driver.
	dosbin "${FILESDIR}"/control_usb_runtime_suspend.sh
	udev_dorules "${FILESDIR}/99-chromeos-puff-usb-runtime-suspend.rules"

	unibuild_install_files audio-files
}
