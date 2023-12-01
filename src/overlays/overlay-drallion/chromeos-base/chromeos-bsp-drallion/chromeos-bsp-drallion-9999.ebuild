# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

# This ebuild only cares about its own FILESDIR and ebuild file, so it tracks
# the canonical empty project.
CROS_WORKON_PROJECT="chromiumos/infra/build/empty-project"
CROS_WORKON_LOCALNAME="platform/empty-project"

inherit appid cros-unibuild udev cros-workon

DESCRIPTION="Drallion board-specific ebuild that pulls in necessary ebuilds as
dependencies or portage actions."

LICENSE="BSD-Google"
KEYWORDS="-* ~amd64 ~x86"
IUSE="modemfwd drallion-kernelnext"

# Add dependencies on other ebuilds from within this board overlay
RDEPEND="
	modemfwd? ( chromeos-base/modemfwd-helpers )
"
DEPEND="
	${RDEPEND}
	chromeos-base/chromeos-config:=
"

src_install() {
	if use drallion-kernelnext; then
		doappid "{4C93DC6D-D00F-4241-A2F5-E5C37E3F210E}" "CHROMEBOOK"
	else
		doappid "{ED3A4869-C380-4F79-A190-027C3E879357}" "CHROMEBOOK"
	fi

	# Intall a rule tagging keyboard as having updated layout
	udev_dorules "${FILESDIR}/81-drallion-keyboard.rules"

	unibuild_install_files audio-files
	unibuild_install_files thermal-files
}
