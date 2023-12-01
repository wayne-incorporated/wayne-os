# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

# Bootstraps rustc (the official Rust compiler) using mrustc (a Rust
# compiler written in C++).
#
# The version of this ebuild reflects the version of rustc that will
# ultimately be installed.
#
# This ebuild can be used in two modes, controlled by the fullbootstrap
# USE flag:
#
# fullbootstrap: Build everything from source. This can take over
#   10 hours.
#
# -fullbootstrap: Start with a prebuilt from an earlier rust-bootstrap
#   and build only versions after that from source.
#
# The default is -fullbootstrap, so that you only get the 10+ hour build
# time if you explicitly request it.

EAPI=7

inherit toolchain-funcs

DESCRIPTION="Bootstraps the rustc Rust compiler using mrustc"
HOMEPAGE="https://github.com/thepowersgang/mrustc"
MRUSTC_VERSION="0.9"
MRUSTC_NAME="mrustc-${MRUSTC_VERSION}"

SLOT="${PV}"
KEYWORDS="*"
IUSE="-fullbootstrap"

INITIAL_RUSTC_VERSION="1.29.0"
# Versions of rustc to build after the initial one.
RUSTC_RAW_FULL_BOOTSTRAP_SEQUENCE=(
	1.30.0
	1.31.1
	1.32.0
	1.33.0
	1.34.2
	1.35.0
	1.36.0
	1.37.0
	1.38.0
	1.39.0
	1.40.0
	1.41.1
	1.42.0
	1.43.1
	1.44.1
	1.45.2
	1.46.0
	1.47.0
	1.48.0
	1.49.0
	1.50.0
	1.51.0
	1.52.0
	1.53.0
	1.54.0
	1.55.0
	1.56.1
	1.57.0
	1.58.1
	1.59.0
	1.60.0
	1.61.0
	1.62.0
	1.63.0
	1.64.0
	1.65.0
	1.66.0
	1.67.0
)

RUSTC_FULL_BOOTSTRAP_SEQUENCE=()

for version in "${RUSTC_RAW_FULL_BOOTSTRAP_SEQUENCE[@]}"; do
	if [[ ! "${PV}" > "${version}" ]]; then
		break
	fi
	RUSTC_FULL_BOOTSTRAP_SEQUENCE+=( "${version}" )
done

# When not using fullbootstrap, use this version as a starting point.
PREBUILT_VERSION="${RUSTC_FULL_BOOTSTRAP_SEQUENCE[-1]}"
SRC_URI="gs://chromeos-localmirror/distfiles/rustc-${PV}-src.tar.gz
	!fullbootstrap? ( gs://chromeos-localmirror/distfiles/rust-bootstrap-${PREBUILT_VERSION}.tbz2 )
	fullbootstrap? ( gs://chromeos-localmirror/distfiles/${MRUSTC_NAME}.tar.gz )
	fullbootstrap? ( gs://chromeos-localmirror/distfiles/rustc-${INITIAL_RUSTC_VERSION}-src.tar.gz )"
for version in "${RUSTC_FULL_BOOTSTRAP_SEQUENCE[@]}"; do
	SRC_URI+=" fullbootstrap? ( gs://chromeos-localmirror/distfiles/rustc-${version}-src.tar.gz )"
done

LICENSE="MIT Apache-2.0 BSD-1 BSD-2 BSD-4 UoI-NCSA"

DEPEND="dev-libs/openssl
	net-libs/libssh2"
RDEPEND="${DEPEND}"

# These tasks take a long time to run for not much benefit: Most of the files
# they check are never installed. Those that are are only there to bootstrap
# the rust ebuild, which has the same RESTRICT anyway.
RESTRICT="binchecks strip"

pkg_setup() {
	if use fullbootstrap; then
		RUSTC_VERSION_SEQUENCE=( "${RUSTC_FULL_BOOTSTRAP_SEQUENCE[@]}" )
		PATCHES=(
			"${FILESDIR}/${PN}-no-curl.patch"
			"${FILESDIR}/${PN}-compilation-fixes.patch"
			"${FILESDIR}/${PN}-8ddb05-invalid-output-constraint.patch"
			"${FILESDIR}/${PN}-libgit2-sys-pkg-config.patch"
			"${FILESDIR}/${PN}-cc.patch"
			"${FILESDIR}/${PN}-printf.patch"
			"${FILESDIR}/${PN}-1.48.0-libc++.patch"
		)
		S="${WORKDIR}/${MRUSTC_NAME}"
	else
		RUSTC_VERSION_SEQUENCE=( )
		# We manually apply patches to rustcs in the version sequence,
		# so that we can pass the necessary -p value. To prevent
		# default from trying and failing to apply patches, we set
		# PATCHES to empty.
		PATCHES=( )
		S="${WORKDIR}/rustc-${PV}-src"
	fi
	RUSTC_VERSION_SEQUENCE+=( ${PV} )
}

src_unpack() {
	default
	if use fullbootstrap; then
		# Move rustc sources to where mrustc expects them.
		mv "${WORKDIR}/rustc-${INITIAL_RUSTC_VERSION}-src" "${S}" || die
	fi
}

src_prepare() {
	# Call the default implementation. This applies PATCHES.
	default

	if use fullbootstrap; then
		# The next few steps mirror what mrustc's Makefile does to configure the
		# build for a specific rustc version.
		(cd "rustc-${INITIAL_RUSTC_VERSION}-src" || die; eapply -p0 "${S}/rustc-${INITIAL_RUSTC_VERSION}-src.patch")
		cd "${S}" || die
		echo "${INITIAL_RUSTC_VERSION}" > "rust-version" || die
		cp "rust-version" "rustc-${INITIAL_RUSTC_VERSION}-src/dl-version" || die
	fi

	# There are some patches that need to be applied to the rustc versions
	# we build with rustc. Apply them here.
	local version
	for version in "${RUSTC_VERSION_SEQUENCE[@]}"; do
		einfo "Patching rustc-${version}"
		# The location of files we patch changed in 1.48.
		# We have patches with no version number for versions
		# before 1.48, and with version number for after.
		local libc_patch="${FILESDIR}/${PN}-1.48.0-libc++.patch"
		if [[ "${version}" < "1.48.0" ]]; then
			libc_patch="${FILESDIR}/${PN}-libc++.patch"
		fi
		(cd "${WORKDIR}/rustc-${version}-src" || die; eapply -p2 "${libc_patch}")

		# In order to build rustc with host=x86_64-pc-linux-gnu, the
		# bootstrap compiler needs to recognize x86_64-pc-linux-gnu.
		local host_patch="${FILESDIR}/rust-bootstrap-add-host-target.patch"
		(cd "${WORKDIR}/rustc-${version}-src" || die; eapply -p1 "${host_patch}")
		(
			cd "${WORKDIR}/rustc-${version}-src/compiler/rustc_target/src/spec" &&
			sed -e 's:"unknown":"pc":g' x86_64_unknown_linux_gnu.rs >x86_64_pc_linux_gnu.rs
		) || die
	done
}

src_configure() {
	# Avoid the default implementation, which overwrites vendored
	# config.guess and config.sub files, which then causes checksum
	# errors during the build, e.g.
	# error: the listed checksum of `/var/tmp/portage/dev-lang/rust-bootstrap-1.46.0/work/rustc-1.46.0-src/vendor/backtrace-sys/src/libbacktrace/config.guess` has changed:
	# expected: 12e217c83267f1ff4bad5d9b2b847032d91e89ec957deb34ec8cb5cef00eba1e
	# actual:   312ea023101dc1de54aa8c50ed0e82cb9c47276316033475ea403cb86fe88ffe
	# (The dev-lang/rust ebuilds in Chrome OS and Gentoo also have custom
	# src_configure implementations.)
	true
}

src_compile() {
	# 1. Build initial rustc using mrustc
	# -----------------------------------
	#
	# All of these specify:
	#  - CC and CXX so that we build with Clang instead of a GCC version that defaults to pre-C99 C.
	#  - LLVM_TARGETS, else it will be empty and rustc will not work.
	#  - RUSTC_VERSION because the Makefiles will otherwise set it to an incorrect value.
	#  - OPENSSL_DIR so that cargo knows where to look for OpenSSL headers.
	export CC=$(tc-getBUILD_CC)
	export CXX=$(tc-getBUILD_CXX)
	export PKG_CONFIG=$(tc-getBUILD_PKG_CONFIG)
	export OPENSSL_DIR="${ESYSROOT}/usr"
	# Only actually build mrustc when using fullbootstrap.
	if use fullbootstrap; then
		# Two separate commands, because invoking just the second command leads to race
		# conditions.
		emake LLVM_TARGETS=X86 RUSTC_VERSION=${INITIAL_RUSTC_VERSION} output/rustc output/cargo
		emake LLVM_TARGETS=X86 RUSTC_VERSION=${INITIAL_RUSTC_VERSION} -C run_rustc
	fi

	# 2. Build successive versions of rustc using previous rustc
	# ----------------------------------------------------------
	if use fullbootstrap; then
		local prev_version=${INITIAL_RUSTC_VERSION}
		local prev_cargo="${S}/run_rustc/output/prefix/bin/cargo"
		local prev_rustc="${S}/run_rustc/output/prefix/bin/rustc"
	else
		local prev_version=${PREBUILT_VERSION}
		local prev_cargo="${WORKDIR}/opt/rust-bootstrap-${PREBUILT_VERSION}/bin/cargo"
		local prev_rustc="${WORKDIR}/opt/rust-bootstrap-${PREBUILT_VERSION}/bin/rustc"
	fi
	local next_version rustc_dir
	for next_version in "${RUSTC_VERSION_SEQUENCE[@]}"; do
		einfo "Building rustc-${next_version} using rustc-${prev_version}"
		# This became necessary in Rust 1.61.0.
		local static_libstdcpp='static-libstdcpp = false'
		if [[ "${next_version}" < "1.61.0" ]]; then
			static_libstdcpp=''
		fi
		rustc_dir="${WORKDIR}/rustc-${next_version}-src"
		cd "${rustc_dir}" || die "Could not chdir to ${rustc_dir}"
		cat > config.toml <<EOF
[build]
cargo = "${prev_cargo}"
rustc = "${prev_rustc}"
docs = false
vendor = true
# extended means we also build cargo and a few other commands.
extended = true
# For rust-bootstrap, we need only cargo.
tools = [ "cargo" ]

[install]
prefix = "${ED}/opt/rust-bootstrap-${next_version}"

[rust]
default-linker = "${CC}"

[llvm]
download-ci-llvm = false
# For rust-bootstrap, we only need x86_64, which LLVM calls X86.
experimental-targets = ""
targets = "X86"
${static_libstdcpp}

[target.x86_64-unknown-linux-gnu]
cc = "${CC}"
cxx = "${CXX}"
linker = "${CC}"
EOF

		# --stage 2 causes this to use the previously-built compiler,
		# instead of the default behavior of downloading one from
		# upstream.
		./x.py --stage 2 build || die
		# For some rustc versions (e.g. 1.31.1), the build script will exit with
		# a nonzero exit status because miri fails to build when it is not in a git
		# repository. This does not affect the ability to build the next rustc.
		# So instead of looking at the exit code, we check if rustc and cargo
		# were built.
		prev_version=${next_version}
		prev_cargo="${rustc_dir}/build/x86_64-unknown-linux-gnu/stage2-tools/x86_64-unknown-linux-gnu/release/cargo"
		prev_rustc="${rustc_dir}/build/x86_64-unknown-linux-gnu/stage2/bin/rustc"
		[[ -x "${prev_rustc}" ]] || die "Failed to build ${prev_rustc}"
		[[ -x "${prev_cargo}" ]] || die "Failed to build ${prev_cargo}"
		einfo "Built rustc-${next_version}"
	done

	# Remove the src/rust symlink which will be dangling after sources are
	# removed, and the containing src directory.
	rm "${WORKDIR}/rustc-${PV}-src/build/x86_64-unknown-linux-gnu/stage2/lib/rustlib/src/rust" || die
	rmdir "${WORKDIR}/rustc-${PV}-src/build/x86_64-unknown-linux-gnu/stage2/lib/rustlib/src" || die
}

src_install() {
	local obj="${WORKDIR}/rustc-${PV}-src/build/x86_64-unknown-linux-gnu/stage2"
	local tools="${obj}-tools/x86_64-unknown-linux-gnu/release/"
	exeinto "/opt/${P}/bin"
	# With rustc-1.45.2 at least, regardless of the value of install.libdir,
	# the rpath seems to end up as $ORIGIN/../lib. So install the libraries there.
	insinto "/opt/${P}/lib"
	doexe "${obj}/bin/rustc"
	doexe "${tools}/cargo"
	doins -r "${obj}/lib/"*
	find "${D}" -name '*.so' -exec chmod +x '{}' ';'
}
