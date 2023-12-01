# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

DESCRIPTION="Proprietary binaries for IPU6EP on Intel ADL platforms"
SRC_URI="https://github.com/intel/ipu6-camera-bins/archive/Chrome_adln_${PV}.tar.gz -> ${P}.tar.gz"

LICENSE="BSD-Intel+patent-grant"
SLOT="0"
KEYWORDS="-* amd64"

RDEPEND="
	!media-libs/intel-ipu6ep-libs-bin
	!media-libs/ipu6ep-firmware
"

S="${WORKDIR}/ipu6-camera-bins-Chrome_adln_${PV}"

src_install() {
	dolib.so usr/"$(get_libdir)"/*.so
	dolib.a usr/"$(get_libdir)"/*.a

	insinto /usr/"$(get_libdir)"/pkgconfig
	doins usr/"$(get_libdir)"/pkgconfig/*.pc

	insinto /lib/firmware/intel
	doins fw/ipu6ep*_fw.bin
}
