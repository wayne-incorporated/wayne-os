# Copyright 2014 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

DESCRIPTION="List of packages that make up the base OS image for koosh"
HOMEPAGE="http://go/koosh"

LICENSE="metapackage"
SLOT="0"
KEYWORDS="*"
IUSE=""

RDEPEND="
	chromeos-base/kexec-init
	sys-apps/kexec-tools
	virtual/target-chromium-os
"
