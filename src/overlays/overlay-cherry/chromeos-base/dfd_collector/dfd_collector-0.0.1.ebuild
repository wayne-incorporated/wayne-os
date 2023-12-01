# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=5

DESCRIPTION="Utilities to collect MTK DFD dumps"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="-* arm64 arm"
IUSE=""
S="${WORKDIR}"

src_install() {
	# Install DFD scripts
	dosbin "${FILESDIR}"/dfd_collector
	insinto /etc/init
	doins "${FILESDIR}"/dfd_collector.conf
}
