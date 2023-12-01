# Copyright 2023 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_COMMIT="d2d95e8af89939f893b1443135497c1f5572aebc"
CROS_WORKON_TREE="776139a53bc86333de8672a51ed7879e75909ac9"
inherit appid cros-unibuild cros-workon udev

# This ebuild only cares about its own FILESDIR and ebuild file, so it tracks
# the canonical empty project.
CROS_WORKON_PROJECT="chromiumos/infra/build/empty-project"
CROS_WORKON_LOCALNAME="platform/empty-project"

DESCRIPTION="Ebuild which pulls in any necessary ebuilds as dependencies
or portage actions."

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="-* arm64 arm"
IUSE=""

# Add dependencies on other ebuilds from within this board overlay
RDEPEND="
	chromeos-base/chromeos-bsp-baseboard-corsola
	chromeos-base/sof-binary
	chromeos-base/sof-topology
"
DEPEND="
	${RDEPEND}
	chromeos-base/chromeos-config
"

src_install() {
	doappid "{DBE80F41-9A47-4CAA-84FE-D1F03153C386}" "CHROMEBOOK"

	# Install audio config files
	unibuild_install_files audio-files

	# Install a rule tagging keyboard as internal
	udev_dorules "${FILESDIR}/91-hammer-keyboard.rules"

	# Install hammerd udev rules and override for chromeos-base/hammerd.
	udev_dorules "${FILESDIR}/99-hammerd.rules"
}
