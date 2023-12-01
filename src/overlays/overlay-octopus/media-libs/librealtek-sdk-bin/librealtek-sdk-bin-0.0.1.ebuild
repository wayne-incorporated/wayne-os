# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=5

inherit multilib

DESCRIPTION="Realtek SDK for USB cameras, binary only install"
SRC_URI="http://commondatastorage.googleapis.com/chromeos-localmirror/distfiles/librealtek-sdk-${PVR}.tgz"

LICENSE="BSD-Realtek"
SLOT="0"
KEYWORDS="-* amd64 x86"

RDEPEND=""

DEPEND="${RDEPEND}
	virtual/pkgconfig"

S="${WORKDIR}"

src_install() {
	dolib.so "librealtek-sdk.so"

	local include_dir="/usr/include/realtek"
	insinto "${include_dir}"
	doins include/rts_descriptor.h include/rts_read_sensor.h

	local in_pc_file=librealtek-sdk.pc.template
	local out_pc_file="${WORKDIR}/${in_pc_file##*/}"
	out_pc_file="${out_pc_file%%.template}"
	local lib_dir
	lib_dir="/usr/$(get_libdir)"

	sed -e "s|@INCLUDE_DIR@|${include_dir}|" -e "s|@LIB_DIR@|${lib_dir}|" \
		"${in_pc_file}" > "${out_pc_file}"
	insinto "${lib_dir}/pkgconfig"
	doins "${out_pc_file}"
}
