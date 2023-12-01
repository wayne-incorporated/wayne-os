# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit toolchain-funcs unpacker

DESCRIPTION="Intel 3A library binaries required by the Intel camera HAL"
SRC_URI="gs://chromeos-localmirror/distfiles/intel-3a-libs-bin-${PV}.tbz2"

LICENSE="BSD-Intel+patent-grant"
SLOT="0"
KEYWORDS="-* amd64"

S="${WORKDIR}"

src_prepare() {
	default
	rm "${S}"/usr/"$(get_libdir)"/libSkyCamAIC.so*
}

src_install() {
	insinto /usr/"$(get_libdir)"
	dolib.so usr/"$(get_libdir)"/*.so*

	insinto /usr/"$(get_libdir)"/pkgconfig
	doins usr/"$(get_libdir)"/pkgconfig/*
}
