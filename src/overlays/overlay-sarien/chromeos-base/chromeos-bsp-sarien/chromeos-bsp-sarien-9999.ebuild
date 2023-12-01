# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

# This ebuild only cares about its own FILESDIR and ebuild file, so it tracks
# the canonical empty project.
CROS_WORKON_PROJECT="chromiumos/infra/build/empty-project"
CROS_WORKON_LOCALNAME="platform/empty-project"

inherit appid cros-unibuild udev cros-workon

DESCRIPTION="Ebuild which pulls in any necessary ebuilds as dependencies
or portage actions."

LICENSE="BSD-Google"
KEYWORDS="-* ~amd64 ~x86"
IUSE="sarien-kvm sarien-kernelnext modemfwd"

# Add dependencies on other ebuilds from within this board overlay
RDEPEND="
	!<chromeos-base/gestures-conf-0.0.2
	modemfwd? ( chromeos-base/modemfwd-helpers )
"
DEPEND="
	${RDEPEND}
	chromeos-base/chromeos-config:=
"

src_install() {
	insinto "/etc/gesture"
	doins "${FILESDIR}"/gesture/*


	if use sarien-kvm; then
		doappid "{3774C742-22BD-4BC5-A052-554CB624433C}" "CHROMEBOOK"
	elif use sarien-kernelnext; then
		doappid "{2E49ECE1-EF84-4D25-AC2F-CC01E117C640}" "CHROMEBOOK"
	else
		doappid "{E3B85B97-1771-4440-9691-D1983FEF60EB}" "CHROMEBOOK"
	fi

	# Install platform-specific internal keyboard keymap. It should probaly
	# go into /lib/udev/hwdb.d but unfortunately udevadm on 64 bit boxes
	# does not check that directory (it wants to look in /lib64/udev).
	insinto "${EPREFIX}/etc/udev/hwdb.d"
	doins "${FILESDIR}/81-sarien-keyboard.hwdb"

	# Intall a rule tagging keyboard as having updated layout
	udev_dorules "${FILESDIR}/81-sarien-keyboard.rules"

	# Install per-board hardware features for Arc++.
	insinto /etc
	doins "${FILESDIR}/hardware_features.xml"
	dosbin "${FILESDIR}/board_hardware_features"

	unibuild_install_files audio-files

	# Arcada use Wacom touch screen with different firmware to support
	# different panels. As a result, we need a way to identify the correct
	# firmware to update. The solution is to probe VID_PID from
	# eDP panel's EDID as a identifier then transfer to Wacom HWID which
	# used to search file names of firmware blobs.
	exeinto "/opt/google/touch/scripts"
	doexe "${FILESDIR}"/arcada/get_board_specific_wacom_hwid.sh
}
