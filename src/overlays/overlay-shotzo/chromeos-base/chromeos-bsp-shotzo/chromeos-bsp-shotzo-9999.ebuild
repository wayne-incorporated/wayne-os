# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

# This ebuild only cares about its own FILESDIR and ebuild file, so it tracks
# the canonical empty project.
CROS_WORKON_PROJECT="chromiumos/infra/build/empty-project"
CROS_WORKON_LOCALNAME="platform/empty-project"

inherit appid cros-unibuild cros-workon

DESCRIPTION="Ebuild which pulls in any necessary ebuilds as dependencies
or portage actions."

LICENSE="BSD-Google"
KEYWORDS="-* ~amd64 ~x86"
IUSE=""

# Add dependencies on other ebuilds from within this board overlay
RDEPEND="
	chromeos-base/sof-binary
	chromeos-base/sof-topology
"

DEPEND="
	${RDEPEND}
	chromeos-base/chromeos-config:=
"

src_install() {
	doappid "{B84E1B34-0D36-4649-A7B6-B64F1BD5AD60}" "CHROMEBASE"

	# Install audio config files
	unibuild_install_files audio-files
}
