# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

CROS_WORKON_COMMIT="d2d95e8af89939f893b1443135497c1f5572aebc"
CROS_WORKON_TREE="776139a53bc86333de8672a51ed7879e75909ac9"
inherit appid cros-unibuild cros-workon udev

# This ebuild only cares about its own FILESDIR and ebuild file, so it tracks
# the canonical empty project.
CROS_WORKON_PROJECT="chromiumos/infra/build/empty-project"
CROS_WORKON_LOCALNAME="platform/empty-project"

DESCRIPTION="keeby board-specific ebuild that pulls in necessary ebuilds as
dependencies or portage actions."

LICENSE="BSD-Google"
KEYWORDS="-* amd64 x86"
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
