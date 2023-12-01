# Copyright 2010 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can
# be found in the LICENSE file.

EAPI=7

DESCRIPTION="Convenience script for testing attached cell modems"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""

RDEPEND="dev-util/shflags
	net-misc/socat"
DEPEND=""

S=${WORKDIR}

src_install() {
	dobin "${FILESDIR}"/modem-diagnostics
	dobin "${FILESDIR}"/qpst_setup
}
