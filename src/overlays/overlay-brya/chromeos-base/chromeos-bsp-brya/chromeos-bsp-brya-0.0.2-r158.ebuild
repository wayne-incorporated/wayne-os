# Copyright 2020 The ChromiumOS Authors
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
IUSE="brya-arc-t adlrvp brya-lvm-stateful zephyr_poc brya-hibernate brya-kernelnext brya-connectivitynext brya-pvs modemfwd"

# Add dependencies on other ebuilds from within this board overlay
RDEPEND="
	!<chromeos-base/gestures-conf-0.0.2
	chromeos-base/chromeos-bsp-baseboard-brya:=
	chromeos-base/sof-binary:=
	chromeos-base/sof-topology:=
	chromeos-base/touch_updater:=
	media-sound/sound_card_init:=
	modemfwd? ( chromeos-base/modemfwd-helpers )
	net-wireless/ax211-updater
"
DEPEND="
	${RDEPEND}
	chromeos-base/chromeos-config:=
"

src_install() {
	insinto "/etc/gesture"
	doins "${FILESDIR}"/gesture/*

	if use brya-arc-t; then
		doappid "{665664DA-5CBF-4B1C-8915-69D2C7361FCB}" "REFERENCE"
	elif use adlrvp; then
		doappid "{CA89482B-8F28-4ED4-B4E0-14C3FB7FCDF3}" "REFERENCE"
	elif use brya-connectivitynext; then
		doappid "{A081017C-BF31-43CA-BA8F-C3B2DD4B308E}" "REFERENCE"
	elif use brya-hibernate; then
		doappid "{A9D880C3-5FE1-4C7F-B948-9ACA87D3F484}" "REFERENCE"
	elif use brya-kernelnext; then
		doappid "{0BB14857-2FC4-4DE2-9739-63F70E978D85}" "REFERENCE"
	elif use brya-lvm-stateful; then
		doappid "{84BBC912-D9F5-4EF2-89B8-7AED7592AB49}" "REFERENCE"
	elif use brya-pvs; then
		doappid "{4B3CA730-C8D3-42F1-8F33-A898F24B1EE5}" "REFERENCE"
	elif use zephyr_poc; then
		doappid "{4E43EBE7-CAE7-4AF7-A2EA-E37B2C3ECE32}" "REFERENCE"
	else
		doappid "{DEB6CEFD-4EEE-462F-AC21-52DF1E17B52F}" "CHROMEBOOK"
	fi

	# Install audio config files
	unibuild_install_files audio-files

	# Install udev rules
	udev_dorules "${FILESDIR}"/udev/*.rules

	# Override for chromeos-base/hpsd
	insinto /etc/init
	doins "${FILESDIR}/hpsd.override"

	# Install Upstart script to fix incorrect CBI values
	insinto /etc/init
	doins "${FILESDIR}/brya-cbi-override.conf"

	# Unconditionally enable hibernate in the brya-hibernate builder,
	# and reduce the hibernate-after-x time to get more hiberate action
	# while dogfooding.
	if use brya-hibernate; then
		insinto "/usr/share/power_manager/board_specific"
		doins "${FILESDIR}"/hibernate-powerd-prefs/*
	fi
}
