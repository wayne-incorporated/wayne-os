# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

# This ebuild only cares about its own FILESDIR and ebuild file, so it tracks
# the canonical empty project.
CROS_WORKON_COMMIT="d2d95e8af89939f893b1443135497c1f5572aebc"
CROS_WORKON_TREE="776139a53bc86333de8672a51ed7879e75909ac9"
CROS_WORKON_PROJECT="chromiumos/infra/build/empty-project"
CROS_WORKON_LOCALNAME="platform/empty-project"

inherit cros-workon

DESCRIPTION="Pulls in any necessary ebuilds as dependencies or portage actions."

LICENSE="BSD-Google"
KEYWORDS="-* amd64 x86"
IUSE="schedutil_governor"

# Add dependencies on other ebuilds from within this board overlay
RDEPEND=""
DEPEND="${RDEPEND}"

src_install() {
	# Install governor config to tune ondemand governor parameters.
	insinto /etc
	if use schedutil_governor; then
		# TODO(b/157953186): select this or the other
		newins "${FILESDIR}"/cpufreq_schedutil.conf cpufreq.conf
	else
		doins "${FILESDIR}"/cpufreq.conf
	fi
}
