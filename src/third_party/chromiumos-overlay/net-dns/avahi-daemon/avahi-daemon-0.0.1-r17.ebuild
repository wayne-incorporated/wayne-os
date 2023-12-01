# Copyright 2023 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

# "cros_workon info" expects these variables to be set, but we don't have a git
# repo, so use the standard empty project.
CROS_WORKON_COMMIT="d2d95e8af89939f893b1443135497c1f5572aebc"
CROS_WORKON_TREE="776139a53bc86333de8672a51ed7879e75909ac9"
CROS_WORKON_PROJECT="chromiumos/infra/build/empty-project"
CROS_WORKON_LOCALNAME="../platform/empty-project"

inherit tmpfiles cros-workon

DESCRIPTION="Install the upstart job that launches avahi."
HOMEPAGE="http://www.chromium.org/"
LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE="wifi_bootstrapping zeroconf"

RDEPEND="
	net-dns/avahi
"

src_install() {
	insinto /etc/init
	if use wifi_bootstrapping || use zeroconf ; then
		newins "${FILESDIR}"/init/auto.conf avahi.conf
	else
		newins "${FILESDIR}"/init/manual.conf avahi.conf
	fi
	newtmpfiles "${FILESDIR}/tmpfiles.conf" avahi.conf
}
