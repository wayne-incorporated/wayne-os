# Copyright 2014 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit appid udev

DESCRIPTION="Ebuild which pulls in any necessary ebuilds as dependencies
or portage actions."

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="-* amd64 x86"
S="${WORKDIR}"

# Add dependencies on other ebuilds from within this board overlay
RDEPEND="
"
DEPEND="${RDEPEND}"

src_install() {
	# Workaround for popping noise on external speaker:
	# http://crbug.com/775486
	udev_dorules "${FILESDIR}"/99-powerknobs-jecht.rules


	# Override default CPU clock speed governor
	insinto "/etc"
	doins "${FILESDIR}"/cpufreq-config/cpufreq.conf
}
