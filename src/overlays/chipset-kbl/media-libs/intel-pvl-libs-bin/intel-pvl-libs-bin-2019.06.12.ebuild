# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=6

inherit toolchain-funcs unpacker

DESCRIPTION="Intel Photography Vision Library binaries required by the Intel camera HAL"
SRC_URI="gs://chromeos-localmirror/distfiles/intel-pvl-libs-bin-${PV}.tbz2"

LICENSE="BSD-Intel+patent-grant"
SLOT="0"
KEYWORDS="-* amd64"

S="${WORKDIR}"

src_install() {
	insinto /usr/"$(get_libdir)"
	dolib.so usr/"$(get_libdir)"/*.so*
}
