# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

# This ebuild only cares about its own FILESDIR and ebuild file, so it tracks
# the canonical empty project.
CROS_WORKON_PROJECT="chromiumos/infra/build/empty-project"
CROS_WORKON_LOCALNAME="platform/empty-project"

inherit appid cros-unibuild cros-workon udev

DESCRIPTION="Ebuild which pulls in any necessary ebuilds as dependencies
or portage actions."

LICENSE="BSD-Google"
KEYWORDS="~* ~amd64 ~x86"
IUSE="skyrim-arc-t skyrim-chausie skyrim-kernelnext"

# Add dependencies on other ebuilds from within this board overlay
RDEPEND="
	chromeos-base/sof-binary
	chromeos-base/sof-topology
	chromeos-base/touch_updater
"
DEPEND="
	${RDEPEND}
	chromeos-base/chromeos-config
"

src_install() {
	if use skyrim-arc-t; then
		doappid "{C370AF51-F808-46B6-9399-74CD87CD9BCC}" "CHROMEBOOK"
	elif use skyrim-chausie; then
		doappid "{DFBA47A4-988E-441D-A7C0-6FCA69C62878}" "CHROMEBOOK"
	elif use skyrim-kernelnext; then
		doappid "{EAAAC01D-3DBC-4F72-A2FF-9233F2838831}" "CHROMEBOOK"
	else
		doappid "{C5536B34-7D24-4CD3-8710-BD674185325B}" "REFERENCE"
	fi

	unibuild_install_files audio-files

	udev_dorules "${FILESDIR}/common/50-mendocino-xhci.rules"
}
