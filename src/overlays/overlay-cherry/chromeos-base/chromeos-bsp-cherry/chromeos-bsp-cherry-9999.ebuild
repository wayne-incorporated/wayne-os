# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

inherit appid arc-build-constants cros-unibuild cros-workon

# This ebuild only cares about its own FILESDIR and ebuild file, so it tracks
# the canonical empty project.
CROS_WORKON_PROJECT="chromiumos/infra/build/empty-project"
CROS_WORKON_LOCALNAME="platform/empty-project"

DESCRIPTION="Ebuild which pulls in any necessary ebuilds as dependencies
or portage actions."

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="-* ~arm64 ~arm"
IUSE="cheets cherry64"

# Add dependencies on other ebuilds from within this board overlay
RDEPEND="
	chromeos-base/chromeos-bsp-baseboard-cherry
	chromeos-base/dfd_collector
	chromeos-base/sof-binary
	chromeos-base/sof-topology
	media-sound/sound_card_init
"
DEPEND="
	${RDEPEND}
	chromeos-base/chromeos-config
"

src_install() {
	if use cherry64; then
		doappid "{3A965B03-9B6D-4111-BD71-53C44B38849B}" "CHROMEBOOK"
	else
		doappid "{D756EC88-0BC0-4875-ABFC-2B67369526AC}" "CHROMEBOOK"
	fi

	# Install audio config files
	unibuild_install_files audio-files

	# Install cpuset adjustments.
	if use cheets; then
		arc-build-constants-configure

		insinto "${ARC_PREFIX:?}/vendor/etc/init"
		doins "${FILESDIR}/init.cpusets.rc"
	fi
}
