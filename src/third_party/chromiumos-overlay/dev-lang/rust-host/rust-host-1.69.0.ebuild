# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

# shellcheck disable=SC2034 # Used by cros-rustc.eclass
RUSTC_TARGET_TRIPLES=(
	x86_64-pc-linux-gnu
)
# shellcheck disable=SC2034 # Used by cros-rustc.eclass
RUSTC_BARE_TARGET_TRIPLES=()

# shellcheck disable=SC2034
PYTHON_COMPAT=( python3_{6..9} )
inherit cros-rustc

KEYWORDS="*"

BDEPEND="sys-devel/llvm"
# dev-lang/rust-1.59.0 introduced the split between dev-lang/rust and
# dev-lang/rust-host; note that here to work around file collisions.
RDEPEND="!<dev-lang/rust-1.59.0"

src_compile() {
	cros-rustc_src_compile
	# Remove the src/rust and rustc-src/rust symlinks which will be dangling
	# after sources are removed, and also the containing src directories.
	for d in rustc-src src ; do
		# shellcheck disable=SC2154 # defined in cros-rustc.eclass
		rm "${CROS_RUSTC_BUILD_DIR}/host/stage2/lib/rustlib/${d}/rust" || die
		rmdir "${CROS_RUSTC_BUILD_DIR}/host/stage2/lib/rustlib/${d}" || die
	done
}

src_install() {
	# shellcheck disable=SC2154 # defined in cros-rustc.eclass
	local obj="${CROS_RUSTC_BUILD_DIR}/host/stage2"
	local tools="${obj}-tools/${CHOST}/release"
	dobin "${obj}/bin/rustc"
	dobin "${tools}/cargo" "${obj}/bin/rust-toolchain-version"
	if ! use rust_profile_frontend_generate && ! use rust_profile_llvm_generate; then
		# These won't be built for an instrumented build.
		dobin "${tools}/rustfmt" "${tools}/cargo-fmt"
		dobin "${tools}/clippy-driver" "${tools}/cargo-clippy"
		dobin "${obj}/bin/rustdoc"
	fi
	dobin src/etc/rust-gdb src/etc/rust-lldb
	insinto "/usr/$(get_libdir)"
	doins -r "${obj}/lib/"*
	doins -r "${obj}/lib64/"*

	insinto "/usr/lib/rustlib/src/rust/"
	doins -r "${S}/library"

	# Install miscellaneous LLVM tools.
	#
	# These tools are already provided in the SDK, but they're built with
	# the version of LLVM built by sys-devel/llvm. Rust uses an independent
	# version of LLVM, so the use of these tools is sometimes necessary to
	# produce artifacts that work with `rustc` and such.
	#
	# Our long-term plan is to have Rust using the same version of LLVM as
	# sys-devel/llvm. When that happens, all of the below will be removed, with
	# the expectation that users will migrate to the LLVM tools on `$PATH`.
	local llvm_tools="${CROS_RUSTC_BUILD_DIR}/host/llvm/bin"
	exeinto "/usr/libexec/rust"
	doexe "${llvm_tools}/llvm-profdata"
}
