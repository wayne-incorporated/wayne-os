# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

inherit appid cros-unibuild cros-workon udev

# This ebuild only cares about its own FILESDIR and ebuild file, so it tracks
# the canonical empty project.
CROS_WORKON_PROJECT="chromiumos/infra/build/empty-project"
CROS_WORKON_LOCALNAME="platform/empty-project"

DESCRIPTION="keeby board-specific ebuild that pulls in necessary ebuilds as
dependencies or portage actions."

LICENSE="BSD-Google"
KEYWORDS="-* ~amd64 ~x86"
IUSE=""

RDEPEND="
	chromeos-base/sof-binary
	chromeos-base/sof-topology
	chromeos-base/touch_updater
"
DEPEND="${RDEPEND}"

src_install() {
	doappid "{C3AEAE91-CD98-3247-57BB-6F8B6C5B7FB1}" "CHROMEBOOK"

	# Install audio config files
	unibuild_install_files audio-files
}
