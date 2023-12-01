# Copyright 2013 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

DESCRIPTION="Generic ebuild which satisifies virtual/chromeos-interface.
This is a direct dependency of chromeos-base/chromeos, but can
be overridden in an overlay for specialized boards.

To satisfy this virtual, a package should cause to be installed everything
a user would need to interact with the system locally."
HOMEPAGE="http://src.chromium.org"

LICENSE="metapackage"
SLOT="0"
KEYWORDS="*"
IUSE="-chromeless_tty"

RDEPEND="
	!chromeless_tty? (
		chromeos-base/chromeos-login
		chromeos-base/chromeos-chrome
	)
"
