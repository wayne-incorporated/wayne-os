# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=5
inherit multilib-minimal arc-build-constants

DESCRIPTION="Ebuild for per-sysroot arc-build components."

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"

RDEPEND=""
DEPEND=""

S=${WORKDIR}

src_compile() {
	arc-build-constants-configure

	# Note that in the code generated below, references to ${SYSROOT} etc. are
	# escaped so they don't get evaluated only at run time of the script.
	# There is one exception for ${ARC_PREFIX} (see the commment below) -
	# if/when this is resolved, the script would be static and there'd be no
	# need to dynamically generate it.
	# TODO(crbug.com/1056100): Consider moving to ${FILESDIR} when the bug is
	# addressed.
	cat > pkg-config <<EOF
#!/bin/bash
case \${ABI} in
arm64|amd64)
	libdir=lib64
	;;
arm|x86)
	libdir=lib
	;;
*)
	echo "Unsupported ABI: \${ABI}" >&2
	exit 1
	;;
esac

export PKG_CONFIG_LIBDIR="\${ARC_SYSROOT}/vendor/\${libdir}/pkgconfig"

# This would normally use just \${SYSROOT}, but platform.eclass re-points
# \${SYSROOT} at \${ARC_SYSROOT}. Note that \${ARC_PREFIX} would better be
# expanded at run time as well, but it's currently not exported into the build
# environment.
# TODO(crbug.com/1056100): Address sysroot confusion.
export PKG_CONFIG_SYSROOT_DIR="\${SYSROOT%${ARC_PREFIX}}"

# Portage will get confused and try to "help" us by exporting this.
# Undo that logic.
unset PKG_CONFIG_PATH

exec /usr/bin/pkg-config "\$@"
EOF
}

install_pc_file() {
	prefix="${ARC_PREFIX}/usr"
	sed \
		-e "s|@lib@|$(get_libdir)|g" \
		-e "s|@prefix@|${prefix}|g" \
		"${PC_SRC_DIR}"/"$1" > "$1" || die
	doins "$1"
}

multilib_src_install() {
	PC_SRC_DIR="${FILESDIR}/${ARC_VERSION_CODENAME}"

	insinto "${ARC_PREFIX}/vendor/$(get_libdir)/pkgconfig"
	install_pc_file backtrace.pc
	install_pc_file cutils.pc
	install_pc_file expat.pc
	install_pc_file hardware.pc
	install_pc_file mediandk.pc
	install_pc_file pthread-stubs.pc
	install_pc_file sync.pc
	install_pc_file zlib.pc

	install_pc_file nativewindow.pc
}

multilib_src_install_all() {
	local bin_dir="${ARC_PREFIX}/build/bin"
	local prebuilt_dir="${ARC_PREFIX}/usr"

	local arc_arch="${ARCH}"
	# arm needs to use arm64 directory, which provides combined arm/arm64
	# headers and libraries.
	if [[ "${ARCH}" == "arm" ]]; then
		arc_arch="arm64"
	fi

	local prebuilt_src="${ARC_BASE}/${arc_arch}/usr"

	exeinto "${bin_dir}"
	doexe pkg-config

	dosym "${prebuilt_src}" "${prebuilt_dir}"
}
