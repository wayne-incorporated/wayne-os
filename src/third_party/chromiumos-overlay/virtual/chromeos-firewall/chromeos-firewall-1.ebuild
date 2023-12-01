# Copyright 2014 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

DESCRIPTION="Chrome OS Firewall virtual package. This package will RDEPEND
on the actual package that installs the upstart scripts to configure the
firewall. Any board overlays that wish to change the firewall settings can
do so with their own virtual package and corresponding ebuild."
HOMEPAGE="http://src.chromium.org"

LICENSE="metapackage"
SLOT="0"
KEYWORDS="*"

RDEPEND="chromeos-base/chromeos-firewall-init"