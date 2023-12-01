# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=5

inherit appid
inherit cros-unibuild

DESCRIPTION="Ebuild which pulls in any necessary ebuilds as dependencies
or portage actions."

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="-* amd64 x86"
IUSE="nami-kvm nami-kernelnext kernel-5_4"
S="${WORKDIR}"

# Add dependencies on other ebuilds from within this board overlay
RDEPEND="
	chromeos-base/rmi4utils
	chromeos-base/chromeos-bsp-baseboard-nami
"
DEPEND="
	${RDEPEND}
	chromeos-base/chromeos-config
"

src_install() {
	if use nami-kvm; then
		doappid "{DB6012BC-8758-4280-B40D-41F2792F46B9}" "CHROMEBOOK"
	elif use nami-kernelnext; then
		doappid "{F21A7EB6-CB05-11EB-B572-CF4C2D968CF6}" "CHROMEBOOK"
	else
		doappid "{495DCB07-E19A-4D7D-99B9-4710011A65B1}" "CHROMEBOOK"
	fi

	unibuild_install_files audio-files
	unibuild_install_files thermal-files

	# Projects might support multiple panels with the same Wacom digitizer
	# chip but have different firmwares for fine-tuned performance.
	# As a result, we need a way to identify the correct firmware to update.
	# The solution is to probe VID_PID from eDP panel's EDID as a identifier
	# to search files names of firmware blobs.
	exeinto "/opt/google/touch/scripts"
	doexe "${FILESDIR}"/get_board_specific_wacom_hwid.sh
}
