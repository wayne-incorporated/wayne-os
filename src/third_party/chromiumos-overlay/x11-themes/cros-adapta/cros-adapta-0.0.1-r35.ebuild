# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=5
CROS_WORKON_COMMIT="46fd2136aa799bb17dfb1002278f98e6397e5806"
CROS_WORKON_TREE="7b93178709970757d72325b63d06bc6935e825c3"
CROS_WORKON_LOCALNAME="cros-adapta"
CROS_WORKON_PROJECT="chromiumos/third_party/cros-adapta"

inherit cros-workon

DESCRIPTION="GTK theme for the VM guest container for Chrome OS"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/third_party/cros-adapta/"

LICENSE="GPL-2 CC-BY-4.0"
SLOT="0"
KEYWORDS="*"

src_install() {
	insinto /opt/google/cros-containers/cros-adapta
	doins -r gtk-2.0 gtk-3.0 gtk-3.22 index.theme

	# Install the assets directory if it exists.
	if [[ -d assets ]] ; then
		doins -r assets
	fi
}
