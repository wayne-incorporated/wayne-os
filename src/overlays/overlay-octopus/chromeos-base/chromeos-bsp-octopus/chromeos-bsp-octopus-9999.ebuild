# Copyright 2017 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

# This ebuild only cares about its own FILESDIR and ebuild file, so it tracks
# the canonical empty project.
CROS_WORKON_PROJECT="chromiumos/infra/build/empty-project"
CROS_WORKON_LOCALNAME="platform/empty-project"

inherit appid
inherit cros-unibuild udev cros-workon

DESCRIPTION="Octopus board-specific ebuild that pulls in necessary ebuilds as
dependencies or portage actions."

LICENSE="BSD-Google"
KEYWORDS="-* ~amd64 ~x86"
IUSE="octopus-arc-r octopus-kernelnext"

# Add dependencies on other ebuilds from within this board overlay
RDEPEND="
	!<chromeos-base/gestures-conf-0.0.2
	chromeos-base/chromeos-bsp-baseboard-octopus:=
"
DEPEND="
	${RDEPEND}
	chromeos-base/chromeos-config:=
"

src_install() {
	insinto "/etc/gesture"
	doins "${FILESDIR}"/gesture/*

	if use octopus-arc-r; then
		doappid "{312CD618-BD44-49ED-9E2B-AB4C5C99BF54}" "CHROMEBOOK"
	elif use octopus-kernelnext; then
		doappid "{37D471DD-3774-4DA2-AF6D-6BA7F5A3B255}" "CHROMEBOOK"
	else
		doappid "{9A3BE5D2-C3DC-4AE6-9943-E2C113895DC5}" "CHROMEBOOK"
	fi

	# Projects might support multiple panels with the same Wacom/Emright digitizer
	# chip but have different firmwares for fine-tuned performance.
	# As a result, we need a way to identify the correct firmware to update.
	# The solution is to probe VID_PID from eDP panel's EDID as a identifier
	# to search files names of firmware blobs.
	exeinto "/opt/google/touch/scripts"
	doexe "${FILESDIR}"/get_board_specific_wacom_hwid.sh
	doexe "${FILESDIR}"/get_board_specific_emright_hwid.sh

	dosbin "${FILESDIR}"/control_usb_charge_mode.sh
	dosbin "${FILESDIR}"/control_usb_runtime_suspend.sh

	unibuild_install_files audio-files
	unibuild_install_files thermal-files

	# Configure Pen Eject as a wakeup source
	udev_dorules "${FILESDIR}/93-powerd-overrides.rules"
	# Monitor udev event for USB A ports to control power of re-driver.
	udev_dorules "${FILESDIR}/99-chromeos-octopus-usb-charge-mode.rules"

	udev_dorules "${FILESDIR}/99-chromeos-octopus-usb-runtime-suspend.rules"
}
