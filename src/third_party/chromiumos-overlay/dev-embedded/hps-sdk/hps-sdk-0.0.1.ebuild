# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

PYTHON_COMPAT=( python3_{6..9} )

inherit cros-constants python-any-r1

DESCRIPTION="Compilers for building HPS firmware"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform/hps-firmware"
LICENSE="|| ( MIT Apache-2.0 ) BSD-1 BSD-2 BSD-4 UoI-NCSA GPL-3 LGPL-3 libgcc FDL-1.2"
KEYWORDS="*"
SLOT="0"

RUST_VERSION="1.62.1"
RUST_BOOTSTRAP_VERSION="1.61.0"
RUST_BOOTSTRAP_HOST_TRIPLE="x86_64-unknown-linux-gnu"
MIRI_REV="ea63a695c8ba0f4322f21074f7646e0ea9f43001"

# These revisions match the submodules in
# https://github.com/riscv-collab/riscv-gnu-toolchain/tree/2021.04.23
BINUTILS_REV="f35674005e609660f5f45005a9e095541ca4c5fe"
GCC_REV="03cb20e5433cd8e65af6a1a6baaf3fe4c72785f6"

SRC_URI="
	https://static.rust-lang.org/dist/rustc-${RUST_VERSION}-src.tar.gz
	https://static.rust-lang.org/dist/rustc-${RUST_BOOTSTRAP_VERSION}-${RUST_BOOTSTRAP_HOST_TRIPLE}.tar.xz
	https://static.rust-lang.org/dist/rust-std-${RUST_BOOTSTRAP_VERSION}-${RUST_BOOTSTRAP_HOST_TRIPLE}.tar.xz
	https://static.rust-lang.org/dist/cargo-${RUST_BOOTSTRAP_VERSION}-${RUST_BOOTSTRAP_HOST_TRIPLE}.tar.xz
	https://github.com/rust-lang/miri/archive/${MIRI_REV}.tar.gz -> miri-${MIRI_REV}.tar.gz
	https://github.com/riscv-collab/riscv-binutils-gdb/archive/${BINUTILS_REV}.tar.gz -> riscv-binutils-gdb-${BINUTILS_REV}.tar.gz
	https://github.com/riscv-collab/riscv-gcc/archive/${GCC_REV}.tar.gz -> riscv-gcc-${GCC_REV}.tar.gz
	ftp://sourceware.org/pub/newlib/newlib-4.1.0.tar.gz
"

S="${WORKDIR}"

pkg_setup() {
	python-any-r1_pkg_setup
}

src_unpack() {
	default

	### RUST ###

	# Copy bootstrap std to where bootstrap rustc will find it
	local rust_std_dir="${WORKDIR}/rust-std-${RUST_BOOTSTRAP_VERSION}-${RUST_BOOTSTRAP_HOST_TRIPLE}/rust-std-${RUST_BOOTSTRAP_HOST_TRIPLE}"
	local rustc_dir="${WORKDIR}/rustc-${RUST_BOOTSTRAP_VERSION}-${RUST_BOOTSTRAP_HOST_TRIPLE}/rustc"
	cp -a \
		"${rust_std_dir}/lib/rustlib/${RUST_BOOTSTRAP_HOST_TRIPLE}" \
		"${rustc_dir}/lib/rustlib/" \
		|| die

	# Replace rustc's bundled copy of miri (which is not expected to work)
	# with the miri we fetched and unpacked
	rm -r "${WORKDIR}/rustc-${RUST_VERSION}-src/src/tools/miri"
	mv "${WORKDIR}/miri-${MIRI_REV}" "${WORKDIR}/rustc-${RUST_VERSION}-src/src/tools/miri"
}

src_prepare() {
	default

	### RUST ###

	cd "${WORKDIR}/rustc-${RUST_VERSION}-src" || die

	# Copy "unknown" vendor targets to create cros_sdk target triple
	# variants as referred to in 0001-add-cros-targets.patch and RUSTC_TARGET_TRIPLES.
	# armv7a is treated specially because the cros toolchain differs in
	# more than just the vendor part of the target triple. The arch is
	# armv7a in cros versus armv7.
	pushd compiler/rustc_target/src/spec || die
	sed -e 's:"unknown":"pc":g' x86_64_unknown_linux_gnu.rs >x86_64_pc_linux_gnu.rs || die
	sed -e 's:"unknown":"cros":g' x86_64_unknown_linux_gnu.rs >x86_64_cros_linux_gnu.rs || die
	sed -e 's:"unknown":"cros":g' armv7_unknown_linux_gnueabihf.rs >armv7a_cros_linux_gnueabihf.rs || die
	sed -e 's:"unknown":"cros":g' aarch64_unknown_linux_gnu.rs >aarch64_cros_linux_gnu.rs || die
	popd || die

	eapply "${FILESDIR}/rust-add-cros-targets.patch"
	eapply "${FILESDIR}/rust-fix-rpath.patch"
	eapply "${FILESDIR}/rust-Revert-CMake-Unconditionally-add-.h-and-.td-files-to.patch"
	eapply "${FILESDIR}/rust-no-test-on-build.patch"
	eapply "${FILESDIR}/rust-sanitizer-supported.patch"
	eapply "${FILESDIR}/rust-cc.patch"
	eapply "${FILESDIR}/rust-revert-libunwind-build.patch"
	eapply "${FILESDIR}/rust-ld-argv0.patch"
	eapply "${FILESDIR}/rust-Handle-sparse-git-repo-without-erroring.patch"
	eapply "${FILESDIR}/rust-disable-mutable-noalias.patch"
	eapply "${FILESDIR}/rust-add-armv7a-sanitizers.patch"
	eapply "${FILESDIR}/rust-passes-only-in-pre-link.patch"
	eapply "${FILESDIR}/rust-Don-t-build-std-for-uefi-targets.patch"
	eapply "${FILESDIR}/rust-Bump-cc-version-in-bootstrap-to-fix-build-of-uefi-ta.patch"

	# For the rustc_llvm module, the build will link with -nodefaultlibs and manually choose the
	# std C++ library. For x86_64 Linux, the build script always chooses libstdc++ which will not
	# work if LLVM was built with USE="default-libcxx". This snippet changes that choice to libc++
	# in the case that clang++ defaults to libc++.
	if "${CXX}" -### -x c++ - < /dev/null 2>&1 | grep -q -e '-lc++'; then
		sed -i 's:"stdc++":"c++":g' compiler/rustc_llvm/build.rs || die
	fi

	### GCC ###

	cd "${WORKDIR}/riscv-gcc-${GCC_REV}" || die
	eapply "${FILESDIR}/gcc-10.2.0-avoid-unprefixed-ld-in-configure-checks.patch"
}

src_configure() {
	### RUST ###

	tc-export PKG_CONFIG

	cd "${WORKDIR}/rustc-${RUST_VERSION}-src" || die
	cat >config.toml <<EOF
[build]
target = [
	"x86_64-unknown-linux-gnu",
	"x86_64-pc-linux-gnu",
	"aarch64-cros-linux-gnu",
	"armv7a-cros-linux-gnueabihf",
	"x86_64-cros-linux-gnu",
	"thumbv6m-none-eabi",
	"riscv32i-unknown-none-elf",
]
cargo = "${WORKDIR}/cargo-${RUST_BOOTSTRAP_VERSION}-${RUST_BOOTSTRAP_HOST_TRIPLE}/cargo/bin/cargo"
rustc = "${WORKDIR}/rustc-${RUST_BOOTSTRAP_VERSION}-${RUST_BOOTSTRAP_HOST_TRIPLE}/rustc/bin/rustc"
docs = false
submodules = false
python = "${EPYTHON}"
vendor = true
extended = true
tools = ["cargo", "cargo-miri", "miri", "src"]
sanitizers = false
profiler = false

[llvm]
ninja = true
targets = "AArch64;ARM;RISCV;X86"
experimental-targets = ""
static-libstdcpp = false

[install]
prefix = "${D}/opt/hps-sdk"
sysconfdir = "etc"
mandir = "share/man"

[rust]
description = "${PF}"
channel = "nightly"
codegen-units = 0
llvm-libunwind = 'in-tree'
codegen-tests = false
new-symbol-mangling = true
lld = false
use-lld = false
default-linker = "${CBUILD}-clang"

[target.x86_64-unknown-linux-gnu]
cc = "${CBUILD}-clang"
cxx = "${CBUILD}-clang++"
linker = "${CBUILD}-clang++"

[target.x86_64-pc-linux-gnu]
cc = "${CBUILD}-clang"
cxx = "${CBUILD}-clang++"
linker = "${CBUILD}-clang++"

[target.aarch64-cros-linux-gnu]
cc = "aarch64-cros-linux-gnu-clang"
cxx = "aarch64-cros-linux-gnu-clang++"
linker = "aarch64-cros-linux-gnu-clang++"

[target.armv7a-cros-linux-gnueabihf]
cc = "armv7a-cros-linux-gnueabihf-clang"
cxx = "armv7a-cros-linux-gnueabihf-clang++"
linker = "armv7a-cros-linux-gnueabihf-clang++"

[target.x86_64-cros-linux-gnu]
cc = "x86_64-cros-linux-gnu-clang"
cxx = "x86_64-cros-linux-gnu-clang++"
linker = "x86_64-cros-linux-gnu-clang++"

[target.thumbv6m-none-eabi]
cc = "armv7m-cros-eabi-clang"
cxx = "armv7m-cros-eabi-clang++"
linker = "armv7m-cros-eabi-clang++"

[target.riscv32i-unknown-none-elf]
cc = "clang"
cxx = "clang++"
linker = "ld.lld"
EOF

	### GCC ###

	# Work around a defective check in libiberty ./configure which invokes unprefixed 'cc'
	export ac_cv_prog_cc_x86_64_pc_linux_gnu_clang_c_o=yes
	export ac_cv_prog_cc_cc_c_o=yes
}

src_compile() {
	### RUST ###

	cd "${WORKDIR}/rustc-${RUST_VERSION}-src" || die
	${EPYTHON} x.py build --stage 2 || die

	### GCC ###

	# Build binutils
	mkdir "${WORKDIR}/build-binutils" || die
	(
		cd "${WORKDIR}/build-binutils" || die
		"${WORKDIR}/riscv-binutils-gdb-${BINUTILS_REV}/configure" \
			--host="${CHOST}" \
			--target=riscv64-unknown-elf \
			--prefix=/opt/hps-sdk \
			--disable-werror \
			--disable-gdb \
			--disable-sim \
			--disable-libdecnumber \
			--disable-readline \
			|| die
		emake
		# Install under $WORKDIR so that GCC stage 1 can find it.
		# We install for real under $D in src_install.
		emake install DESTDIR="${WORKDIR}/installed-stage1"
	)

	# Build GCC stage 1
	mkdir "${WORKDIR}/build-gcc-stage1" || die
	(
		# shellcheck disable=SC2030,SC2031  # subshell is intentional
		export PATH="${WORKDIR}/installed-stage1/opt/hps-sdk/bin:${PATH}"
		cd "${WORKDIR}/build-gcc-stage1" || die
		"${WORKDIR}/riscv-gcc-${GCC_REV}/configure" \
			--host="${CHOST}" \
			--target=riscv64-unknown-elf \
			--prefix="${WORKDIR}/installed-stage1/opt/hps-sdk" \
			--with-sysroot="${WORKDIR}/installed-stage1/opt/hps-sdk/riscv64-unknown-elf" \
			--disable-shared \
			--disable-threads \
			--disable-tls \
			--enable-languages=c,c++ \
			--with-system-zlib \
			--with-newlib \
			--disable-libmudflap \
			--disable-libssp \
			--disable-libquadmath \
			--disable-libgomp \
			--disable-nls \
			--disable-tm-clone-registry \
			--src="${WORKDIR}/riscv-gcc-${GCC_REV}" \
			--enable-multilib \
			--with-multilib-generator="rv32im-ilp32--" \
			CFLAGS_FOR_TARGET="-Os" \
			CXXFLAGS_FOR_TARGET="-Os" \
			|| die
		emake all-gcc
		emake install-gcc
	)

	# Build newlib
	mkdir "${WORKDIR}/build-newlib" || die
	(
		# shellcheck disable=SC2030,SC2031  # subshell is intentional
		export PATH="${WORKDIR}/installed-stage1/opt/hps-sdk/bin:${PATH}"
		cd "${WORKDIR}/build-newlib" || die
		# TODO(dcallagh): should use the "nano" configuration with -Os probably
		"${WORKDIR}/newlib-4.1.0/configure" \
			--host="${CHOST}" \
			--target=riscv64-unknown-elf \
			--prefix=/opt/hps-sdk \
			--enable-newlib-io-long-double \
			--enable-newlib-io-long-long \
			--enable-newlib-io-c99-formats \
			--enable-newlib-register-fini \
			CFLAGS_FOR_TARGET="-O2 -D_POSIX_MODE" \
			CXXFLAGS_FOR_TARGET="-O2 -D_POSIX_MODE" \
			|| die
		emake
		emake install DESTDIR="${WORKDIR}/installed-stage1"
	)

	# Build GCC stage 2
	mkdir "${WORKDIR}/build-gcc-stage2" || die
	(
		# shellcheck disable=SC2030,SC2031  # subshell is intentional
		export PATH="${WORKDIR}/installed-stage1/opt/hps-sdk/bin:${PATH}"
		cd "${WORKDIR}/build-gcc-stage2" || die
		# TODO(dcallagh): the riscv-gnu-toolchain Makefile passes --enable-tls
		# here, but I don't think it's wanted and I don't see how it could work
		"${WORKDIR}/riscv-gcc-${GCC_REV}/configure" \
			--host="${CHOST}" \
			--target=riscv64-unknown-elf \
			--prefix=/opt/hps-sdk \
			--with-sysroot=/opt/hps-sdk/riscv64-unknown-elf \
			--with-build-sysroot="${WORKDIR}/installed-stage1/opt/hps-sdk/riscv64-unknown-elf" \
			--with-native-system-header-dir=/include \
			--disable-shared \
			--disable-threads \
			--disable-tls \
			--enable-languages=c,c++ \
			--with-system-zlib \
			--with-newlib \
			--disable-libmudflap \
			--disable-libssp \
			--disable-libquadmath \
			--disable-libgomp \
			--disable-nls \
			--disable-tm-clone-registry \
			--src="${WORKDIR}/riscv-gcc-${GCC_REV}" \
			--enable-multilib \
			--with-multilib-generator="rv32im-ilp32--" \
			CFLAGS_FOR_TARGET="-Os" \
			CXXFLAGS_FOR_TARGET="-Os" \
			|| die
		emake
	)
}

src_install() {
	### RUST ###

	cd "${WORKDIR}/rustc-${RUST_VERSION}-src" || die
	${EPYTHON} x.py install || die

	### GCC ###

	# shellcheck disable=SC2030,SC2031  # subshell is intentional
	export PATH="${WORKDIR}/installed-stage1/opt/hps-sdk/bin:${PATH}"
	emake -C "${WORKDIR}/build-binutils" install DESTDIR="${D}"
	emake -C "${WORKDIR}/build-newlib" install DESTDIR="${D}"
	emake -C "${WORKDIR}/build-gcc-stage2" install DESTDIR="${D}"
}
