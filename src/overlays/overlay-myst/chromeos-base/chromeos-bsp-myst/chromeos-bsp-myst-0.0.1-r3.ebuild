# Copyright 2023 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

# This ebuild only cares about its own FILESDIR and ebuild file, so it tracks
# the canonical empty project.
CROS_WORKON_COMMIT="d2d95e8af89939f893b1443135497c1f5572aebc"
CROS_WORKON_TREE="776139a53bc86333de8672a51ed7879e75909ac9"
CROS_WORKON_PROJECT="chromiumos/infra/build/empty-project"
CROS_WORKON_LOCALNAME="platform/empty-project"

inherit appid cros-unibuild cros-workon

DESCRIPTION="Ebuild which pulls in any necessary ebuilds as dependencies
or portage actions."

LICENSE="BSD-Google"
KEYWORDS="* amd64 x86"
IUSE="birman"

# Add dependencies on other ebuilds from within this board overlay
RDEPEND=""
DEPEND="
	${RDEPEND}
	chromeos-base/chromeos-config
"

src_install() {
	if use birman; then
		doappid "{91CE340A-9272-4019-B14B-59C00F926DFA}" "OTHER"
	else
		doappid "{5ECED2E3-D919-4DF9-B42A-C9FC136C55BD}" "REFERENCE"
	fi
	# Install cpufreq driver config.
	insinto /etc
	doins "${FILESDIR}"/cpufreq.conf
}
