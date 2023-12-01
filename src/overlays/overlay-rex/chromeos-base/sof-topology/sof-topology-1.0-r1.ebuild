# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

DESCRIPTION="SOF topology files for Rex"
SRC_URI="gs://chromeos-localmirror/distfiles/${PN}-rex-${PV}.tar.gz"

LICENSE="SOF"
SLOT="0"
KEYWORDS="*"

S=${WORKDIR}/${PN}-rex-${PV}

src_install() {
	insinto /lib/firmware/intel/sof-ace-tplg
	doins ./*.tplg
}
