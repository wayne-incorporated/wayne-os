# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit appid cros-workon

# This ebuild only cares about its own FILESDIR and ebuild file, so it tracks
# the canonical empty project.
CROS_WORKON_PROJECT="chromiumos/infra/build/empty-project"
CROS_WORKON_LOCALNAME="platform/empty-project"

DESCRIPTION="Ebuild which pulls in any necessary ebuilds as dependencies
or portage actions."

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="-* ~arm64 ~arm"
IUSE=""

DEPEND="
	chromeos-base/chromeos-bsp-baseboard-herobrine
"

RDEPEND="
	${DEPEND}
"

src_install() {
	doappid "{87C6EED8-5B12-A5C8-7119-6ADCF88CBC80}" "CHROMEBOOK"
}
