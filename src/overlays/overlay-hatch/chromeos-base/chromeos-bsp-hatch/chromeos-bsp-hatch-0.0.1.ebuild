# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=6

inherit appid cros-unibuild

DESCRIPTION="Ebuild which pulls in any necessary ebuilds as dependencies
or portage actions."

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="-* amd64 x86"
IUSE="hatch-arc-r hatch-arc-t hatch-borealis hatch-diskswap hatch-kvm hatch-kernelnext hatch-connectivitynext hatch-manatee aurora aurora-borealis hatch-lvm-stateful kernel-4_19"
S="${WORKDIR}"

# Add dependencies on other ebuilds from within this board overlay
RDEPEND="
	!<chromeos-base/gestures-conf-0.0.2
	kernel-4_19? ( chromeos-base/sof-binary chromeos-base/sof-topology )
	!kernel-4_19? ( sys-firmware/sof-firmware )
	media-sound/sound_card_init
"
DEPEND="
	${RDEPEND}
	chromeos-base/chromeos-config
"

src_install() {
	insinto "/etc/gesture"
	doins "${FILESDIR}"/gesture/*

	if use aurora-borealis; then
		doappid "{567CE7C6-688F-897C-6C1A-0F4C15CC24E7}" "CHROMEBOOK"
	elif use aurora; then
		doappid "{DD70ECA8-C39D-2BAA-055C-9094D3A78BE1}" "CHROMEBOOK"
	elif use hatch-arc-r; then
		doappid "{CB69812A-95B6-4A60-A5D1-AE50E1FC5882}" "CHROMEBOOK"
	elif use hatch-arc-t; then
		doappid "{11AA9F9B-0DF2-4816-8745-3F3C2DC11AB7}" "CHROMEBOOK"
	elif use hatch-borealis; then
		doappid "{8CD2059E-B678-11EA-BEA0-BFD4C54FEC76}" "CHROMEBOOK"
	elif use hatch-diskswap; then
		doappid "{6FBDA804-5618-89BA-5D6E-F3804BDE0EF3}" "CHROMEBOOK"
	elif use hatch-kvm; then
		doappid "{4D5CCCEE-A214-4CFD-9A9F-85DFCF7A0CD4}" "CHROMEBOOK"
	elif use hatch-kernelnext; then
		doappid "{9DFA3334-7067-11EA-A862-83D15EF402B8}" "CHROMEBOOK"
	elif use hatch-connectivitynext; then
		doappid "{ED913761-52D5-4ED2-8043-598C58F2AAA0}" "CHROMEBOOK"
	elif use hatch-manatee; then
		doappid "{D9FC4642-8B32-11EB-ADCB-C7CD28B0A950}" "CHROMEBOOK"
	elif use hatch-lvm-stateful; then
		doappid "{0C8FD4CA-1AE6-4447-8F73-83D11C1FD602}" "CHROMEBOOK"
	else
		doappid "{95EE134E-B47F-43FB-9835-32C276865F9A}" "CHROMEBOOK"
	fi

	unibuild_install_files audio-files

	unibuild_install_files autobrightness-files
}
