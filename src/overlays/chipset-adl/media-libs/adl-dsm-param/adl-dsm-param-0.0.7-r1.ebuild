# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

DESCRIPTION="tgl tuning DSM Param"
SRC_URI="gs://chromeos-localmirror/distfiles/adl-dsm-param-brya-${PV}.tar.bz2"

LICENSE="LICENSE.dsm"
SLOT="0"
KEYWORDS="-* x86 amd64"

S="${WORKDIR}"

src_install() {
	insinto /opt/google/dsm
	doins ./*.bin
}
