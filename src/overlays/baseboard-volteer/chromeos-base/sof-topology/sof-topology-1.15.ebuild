# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=5

# Version of the topology package that needs to be downloaded. This should be
# updated when a new topology is required to be used.
TARBALL_NAME="${P}-volteer"

DESCRIPTION="Topology file needed to run SOF."
SRC_URI="gs://chromeos-localmirror/distfiles/${PN}-volteer-${PV}.tar.bz2"

LICENSE="SOF"
SLOT="0"
KEYWORDS="*"
IUSE=""

S="${WORKDIR}"/"${PN}-volteer-${PV}"

src_install() {
	insinto /lib/firmware/intel/sof-tplg
	doins *.tplg
	insinto /lib/firmware/intel/sof-tplg/pdm1
	doins pdm1/*.tplg
	insinto /lib/firmware/intel/sof-tplg/pdm1-drceq
	doins pdm1-drceq/*.tplg
	dodoc README
}
