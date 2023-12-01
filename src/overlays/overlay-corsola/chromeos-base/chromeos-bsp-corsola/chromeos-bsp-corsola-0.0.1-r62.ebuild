# Copyright 2021 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_COMMIT="d2d95e8af89939f893b1443135497c1f5572aebc"
CROS_WORKON_TREE="776139a53bc86333de8672a51ed7879e75909ac9"
inherit appid cros-unibuild cros-workon

# This ebuild only cares about its own FILESDIR and ebuild file, so it tracks
# the canonical empty project.
CROS_WORKON_PROJECT="chromiumos/infra/build/empty-project"
CROS_WORKON_LOCALNAME="platform/empty-project"

DESCRIPTION="Ebuild which pulls in any necessary ebuilds as dependencies
or portage actions."

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="-* arm64 arm"
IUSE="corsola-arc-t corsola-kernelnext"

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
	if use corsola-arc-t; then
		doappid "{6EBDE1FC-D0DB-4BB4-B9E7-23EBFBB72123}" "CHROMEBOOK"
	elif use corsola-kernelnext; then
		doappid "{A373B826-5687-43D0-B5D1-E049E1683F50}" "CHROMEBOOK"
	else
		doappid "{3C9B1B3B-E594-448D-97A7-B3A2568BCC5C}" "CHROMEBOOK"
	fi

	# Install audio config files
	unibuild_install_files audio-files
}
