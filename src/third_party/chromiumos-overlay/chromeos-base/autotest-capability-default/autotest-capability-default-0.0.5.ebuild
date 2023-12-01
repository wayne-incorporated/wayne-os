# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

DESCRIPTION="Install the default autotest labels"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""
S="${WORKDIR}"

src_install() {
	insinto /etc/autotest-capability/
	doins -r "${FILESDIR}"/*
}
