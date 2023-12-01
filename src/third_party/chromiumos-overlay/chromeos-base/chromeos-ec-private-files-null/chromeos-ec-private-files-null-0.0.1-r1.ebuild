# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=5

DESCRIPTION="Chromium Embedded Controller private files placeholder"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"

S=${WORKDIR}

src_install() {
	# Empty directory, we have no private sources
	dodir /firmware/ec-private
}
