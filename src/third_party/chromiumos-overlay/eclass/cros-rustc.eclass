# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

# @ECLASS: cros-rustc.eclass
# @MAINTAINER:
# The Chromium OS Toolchain Team <chromeos-toolchain@google.com>
# @BUGREPORTS:
# Please report bugs via
# https://issuetracker.google.com/issues/new?component=1038090&template=1576440
# @VCSURL: https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/HEAD/eclass/@ECLASS@
# @BLURB: Eclass for building CrOS' Rust toolchain.
# @DESCRIPTION:
# This eclass is used to build both dev-lang/rust-host and dev-lang/rust.
#
# dev-lang/rust-host is an ebuild that provides all artifacts necessary for
# building Rust for the host. dev-lang/rust supplements this with libraries for
# cross-compiling. We maintain this split because we need to build Rust
# binaries for the host prior to cross-* libraries being available.
#
# An important concept when building dev-lang/rust-host and dev-lang/rust is
# continuity: these packages are expected to be built from _identical_ Rust
# sources. This assumption:
# - doesn't restrict us in any meaningful way,
# - keeps us more consistent with upstream flows for building `rustc`, and
# - allows us to significantly cut down on the build time of dev-lang/rust,
#   since dev-lang/rust can skip unpacking sources, configuring them, and
#   rebuilding LLVM + stage0 + stage1.
#
# Moreover, if you want to make meaningful changes to Rust, you'll need to
# always reemerge _both_ dev-lang/rust-host and dev-lang/rust. dev-lang/rust
# assumes that the sources unpacked by dev-lang/rust-host, if present, are
# identical to the ones it will build. dev-lang/rust-host always starts with a
# clean slate.

if [[ -z ${_ECLASS_CROS_RUSTC} ]]; then
_ECLASS_CROS_RUSTC="1"

# Check for EAPI 7+.
case "${EAPI:-0}" in
[0123456]) die "unsupported EAPI (${EAPI}) in eclass (${ECLASS})" ;;
esac

EXPORT_FUNCTIONS pkg_setup src_unpack src_prepare src_configure src_compile

PYTHON_COMPAT=( python3_{6..9} )
inherit cros-llvm cros-constants git-r3 python-any-r1 toolchain-funcs

CROS_RUSTC_DIR="${SYSROOT}/var/cache/portage/${CATEGORY}/rust-artifacts"
CROS_RUSTC_BUILD_DIR="${CROS_RUSTC_DIR}/build"
CROS_RUSTC_SRC_DIR="${CROS_RUSTC_DIR}/src"
CROS_RUSTC_LLVM_SRC_DIR="${CROS_RUSTC_DIR}/llvm-project"

# It's intended that only a person upgrading the Rust version used in ChromeOS
# needs to worry about these flags.
#
# These flags control whether to build a compiler that will generate PGO
# profiles, or build a compiler using PGO profiles obtained locally, or build a
# compiler using PGO profiles obtained from gs (the default).
#
# rust_profile_frontend_generate causes the Rust compiler to be built
# with instrumentation in the frontend code for generating PGO profiles,
# which will be stored in "${CROS_RUSTC_PGO_LOCAL_BASE}/frontend-profraw"
#
# rust_profile_llvm_generate causes the Rust compiler to be built
# with instrumentation in the LLVM code for generating PGO profiles,
# which will be stored in "${CROS_RUSTC_PGO_LOCAL_BASE}/llvm-profraw"
#
# The two *_generate flags cannot be used together; the implementation here
# asserts against this possibility. Currently if we try to instrument both
# components at once, we get an error about different profiler versions. Maybe
# this can be changed when Rust uses the same LLVM as sys-devel/llvm.
#
# rust_profile_frontend_use will cause a frontend profdata file to be
# downloaded from
# "gs://chromeos-localmirror/distfiles/rust-pgo-${PV}-frontend.profdata.xz" and
# used for PGO optimization.
#
# rust_profile_frontend_use_local will instead use a frontend profdata file at
# ${FILESDIR}/frontend.profdata
#
# rust_profile_llvm_use will cause an llvm profdata file to be downloaded from
# "gs://chromeos-localmirror/distfiles/rust-pgo-${PV}-llvm.profdata.xz" and
# used for PGO optimization.
#
# rust_profile_llvm_use_local will instead use a llvm profdata file at
# ${FILESDIR}/llvm.profdata
IUSE='rust_profile_frontend_generate rust_profile_llvm_generate rust_profile_frontend_use_local rust_profile_llvm_use_local +rust_profile_frontend_use +rust_profile_llvm_use +rust_cros_llvm'

REQUIRED_USE="
	rust_profile_frontend_generate? (
		!rust_profile_frontend_use
		!rust_profile_frontend_use_local
		!rust_profile_llvm_use
		!rust_profile_llvm_use_local
	)
	rust_profile_llvm_generate? (
		!rust_profile_frontend_use
		!rust_profile_frontend_use_local
		!rust_profile_llvm_use
		!rust_profile_llvm_use_local
	)
	rust_profile_llvm_use? ( !rust_profile_llvm_use_local )
	rust_profile_frontend_use? ( !rust_profile_frontend_use_local )
"

# @ECLASS-VARIABLE: RUSTC_TARGET_TRIPLES
# @DEFAULT_UNSET
# @REQUIRED
# @DESCRIPTION:
# This is the list of target triples for rustc as they appear in the cros_sdk.
# cros-rust_src_configure instructs cros-rust_src_compile to use
# "${triple}-clang" when building each one of these.

# @ECLASS-VARIABLE: RUSTC_BARE_TARGET_TRIPLES
# @DEFAULT_UNSET
# @DESCRIPTION:
# These are the triples we use GCC with. `*-cros-*` triples should not be
# included here.

# @ECLASS-VARIABLE: CROS_RUSTC_BUILD_RAW_SOURCES
# @DEFAULT_UNSET
# @DESCRIPTION:
# Set to a nonempty value if we want to build a nonstandard set of sources
# (this is intended mostly to power bisection of rustc itself).
# This should never be set to anything in production.
#
# If you want to set this as a user, each `emerge` of `dev-lang/rust-host` or
# `dev-lang/rust` assumes the following:
# 1. A full Rust checkout is available under `_CROS_RUSTC_RAW_SOURCES_ROOT`.
# 2. You've ensured that all submodules under `_CROS_RUSTC_RAW_SOURCES_ROOT` are
#    up-to-date with your currently checked out revision.
# 3. You've ensured that the appropriate bootstrap compiler is cached under
#    `_CROS_RUSTC_RAW_SOURCES_ROOT/build`.
# 4. You've run `cargo vendor` under `_CROS_RUSTC_RAW_SOURCES_ROOT`
# 5. The sources under `_CROS_RUSTC_RAW_SOURCES_ROOT` are the exact sources you
#    want to apply `${PATCHES}` to.
# 6. You are OK with this script modifying your rustc sources at
#    `_CROS_RUSTC_RAW_SOURCES_ROOT` (by applying patches to them).
#
# Step 2 can be done with
# `dev-lang/rust/files/bisect-scripts/clean_and_sync_rust_root.sh`. Steps 3 and
# 4 can be accomplished with
# `dev-lang/rust/files/bisect-scripts/prepare_rust_for_offline_build.sh`.
CROS_RUSTC_BUILD_RAW_SOURCES=

# We identify the .profdata file we want by ${PV}. Sometimes we may want to
# upload and use a newer profdata file even if we haven't bumped PV; these can
# be distinguished with this suffix.
PROFDATA_SUFFIX=""

# There's a fair amount of direct commonality between dev-lang/rust and
# dev-lang/rust-host. Capture that here.
ABI_VER="$(ver_cut 1-2)"
SLOT="stable/${ABI_VER}"
MY_P="rustc-${PV}"
SRC="${MY_P}-src.tar.gz"

# The version of rust-bootstrap that we're using to build our current Rust
# toolchain. This is generally the version released prior to the current one,
# since Rust uses the beta compiler to build the nightly compiler.
BOOTSTRAP_VERSION="1.68.0"

# The commit we're using for our LLVM.
LLVM_EGIT_COMMIT="2916b99182752b1aece8cc4479d8d6a20b5e02da" # r484197

# If `CROS_RUSTC_BUILD_RAW_SOURCES` is nonempty, a full Rust source tree is
# expected to be available here.
_CROS_RUSTC_RAW_SOURCES_ROOT="${FILESDIR}/rust"

HOMEPAGE="https://www.rust-lang.org/"

if [[ -z "${CROS_RUSTC_BUILD_RAW_SOURCES}" ]]; then
	SRC_URI="
		https://static.rust-lang.org/dist/${SRC} -> rustc-${PV}-src.tar.gz
		rust_profile_frontend_use? ( gs://chromeos-localmirror/distfiles/rust-pgo-${PV}${PROFDATA_SUFFIX}-frontend.profdata.xz )
		rust_profile_llvm_use? ( gs://chromeos-localmirror/distfiles/rust-pgo-${PV}${PROFDATA_SUFFIX}-llvm.profdata.xz )
	"
else
	SRC_URI="
		rust_profile_frontend_use? ( gs://chromeos-localmirror/distfiles/rust-pgo-${PV}${PROFDATA_SUFFIX}-frontend.profdata.xz )
		rust_profile_llvm_use? ( gs://chromeos-localmirror/distfiles/rust-pgo-${PV}${PROFDATA_SUFFIX}-llvm.profdata.xz )
	"
	# If a bisection is happening, we use the bootstrap compiler that upstream prefers.
	# Clear this so we don't accidentally use it below.
	BOOTSTRAP_VERSION=
fi

LICENSE="|| ( MIT Apache-2.0 ) BSD-1 BSD-2 BSD-4 UoI-NCSA"

RESTRICT="binchecks strip"

DEPEND="${PYTHON_DEPS}
	>=dev-libs/libxml2-2.9.6
	>=dev-lang/perl-5.0
"

if [[ -z "${CROS_RUSTC_BUILD_RAW_SOURCES}" ]]; then
	DEPEND+="dev-lang/rust-bootstrap:${BOOTSTRAP_VERSION}"
fi

PATCHES=(
	"${FILESDIR}/rust-force-host-triple.patch"
	"${FILESDIR}/rust-add-cros-targets.patch"
	"${FILESDIR}/rust-fix-rpath.patch"
	"${FILESDIR}/rust-sanitizer-supported.patch"
	"${FILESDIR}/rust-cc.patch"
	"${FILESDIR}/rust-revert-libunwind-build.patch"
	"${FILESDIR}/rust-ld-argv0.patch"
	"${FILESDIR}/rust-Handle-sparse-git-repo-without-erroring.patch"
	"${FILESDIR}/rust-add-armv7a-sanitizers.patch"
	"${FILESDIR}/rust-bootstrap-use-CARGO_HOME.patch"
	"${FILESDIR}/rust-ignore-version-in-mangling.patch"
	"${FILESDIR}/rust-rustc_llvm-stage0-is-not-cross-compiling.patch"
	"${FILESDIR}/rust-use-adt-triple.patch"
)

# shellcheck disable=SC2154 # defined by cros-rustc-directories
S="${CROS_RUSTC_SRC_DIR}/${MY_P}-src"

_CROS_RUSTC_PREPARED_STAMP="${CROS_RUSTC_SRC_DIR}/cros-rust-prepared"
# shellcheck disable=SC2154 # defined by cros-rustc-directories
_CROS_RUSTC_STAGE1_EXISTS_STAMP="${CROS_RUSTC_BUILD_DIR}/cros-rust-has-stage1-build"

CROS_RUSTC_PGO_LOCAL_BASE='/tmp/rust-pgo'

# @FUNCTION: cros-rustc_has_existing_checkout
# @DESCRIPTION:
# Tests whether we have a properly src_prepare'd checkout in ${CROS_RUSTC_DIR}.
cros-rustc_has_existing_checkout() {
	[[ -e "${_CROS_RUSTC_PREPARED_STAMP}" ]]
}

# @FUNCTION: cros-rustc_has_existing_stage1_build
# @DESCRIPTION:
# Tests whether ${CROS_RUSTC_BUILD_DIR} has a valid stage1 toolchain available.
cros-rustc_has_existing_stage1_build() {
	[[ -e "${_CROS_RUSTC_STAGE1_EXISTS_STAMP}" ]]
}

cros-rustc_pkg_setup() {
	python-any-r1_pkg_setup

	if [[ ${MERGE_TYPE} != "binary" ]]; then
		# shellcheck disable=SC2154 # defined by cros-rustc-directories
		addwrite "${CROS_RUSTC_DIR}"
		# Disable warnings about 755 only applying to the deepest
		# directory; that's fine.
		# shellcheck disable=SC2174
		mkdir -p -m 755 "${CROS_RUSTC_DIR}"
		chown "${PORTAGE_USERNAME}:${PORTAGE_GRPNAME}" "${CROS_RUSTC_DIR}"

		if [[ -n "${CROS_RUSTC_BUILD_RAW_SOURCES}" ]]; then
			addwrite "${_CROS_RUSTC_RAW_SOURCES_ROOT}"
			ewarn "cros-rustc.eclass is using raw sources. This feature is for debugging only."
		fi
	fi
}

# Sets up portage directories for a build. Expects that ${CROS_RUSTC_SRC_DIR}
# exists and is properly set up.
# This should be called during src_unpack if you opt out of calling
# `cros-rustc_src_unpack`. Otherwise, `cros-rustc_src_unpack` will take care of
# this.
cros-rustc_setup_portage_dirs() {
	# Sets up a cargo config.toml that instructs our bootstrap rustc to use
	# the correct linker. `rust-bootstrap` can be made to work around this
	# since we have local patches, but bootstrap compilers downloaded from
	# upstream (e.g., during bisection) cannot.
	export CARGO_HOME="${T}/cargo_home"
	mkdir -p "${CARGO_HOME}" || die
	cat >> "${CARGO_HOME}/config.toml" <<EOF || die

[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "${S}/vendor"

[target.x86_64-unknown-linux-gnu]
linker = "${CHOST}-clang"

[target.${CHOST}]
linker = "${CHOST}-clang"
EOF

	# Mirror licenses, so Portage license tooling can find them easily.
	local targ="${WORKDIR}/licenses"
	local src="${CROS_RUSTC_SRC_DIR}"
	if [[ -n "${CROS_RUSTC_BUILD_RAW_SOURCES}" ]]; then
		src="${_CROS_RUSTC_RAW_SOURCES_ROOT}"
	fi
	mkdir -p "${targ}" || die
	einfo "Mirroring licenses from ${CROS_RUSTC_SRC_DIR} into ${targ}..."
	rsync -rl --include='*/' --include='LICENSE*' --exclude='*' \
		--prune-empty-dirs "${src}" "${targ}" || die
}

_cros-rustc_unpack_llvm_sources() {
	einfo "Unpacking LLVM sources..."

	local EGIT_REPO_URI="${CROS_GIT_HOST_URL}/external/github.com/llvm/llvm-project
		${CROS_GIT_HOST_URL}/external/github.com/llvm/llvm-project"
	local EGIT_BRANCH=main
	# shellcheck disable=SC2154 # defined by cros-rustc-directories
	local EGIT_CHECKOUT_DIR="${CROS_RUSTC_LLVM_SRC_DIR}"
	local EGIT_COMMIT="${LLVM_EGIT_COMMIT}"
	git-r3_src_unpack
	# git-r3_src_unpack won't freshly unpack sources if they're already
	# there, so we do the following to get to a clean state.
	git -C "${EGIT_CHECKOUT_DIR}" reset --hard HEAD || die
	git -C "${EGIT_CHECKOUT_DIR}" clean -fd || die
}

cros-rustc_src_unpack() {
	if [[ -n "${CROS_RUSTC_BUILD_RAW_SOURCES}" ]]; then
		if [[ ! -d "${_CROS_RUSTC_RAW_SOURCES_ROOT}" ]]; then
			eerror "You must have a full Rust checkout in _CROS_RUSTC_RAW_SOURCES_ROOT."
			die
		fi
		if [[ -e "${S}" && ! -L "${S}" ]]; then
			rm -rf "${S}" || die
		fi
		# It's OK if 755 applies to the deepest directory.
		# shellcheck disable=SC2174
		mkdir -p -m 755 "${CROS_RUSTC_SRC_DIR}"
		ln -sf "$(readlink -m "${_CROS_RUSTC_RAW_SOURCES_ROOT}")" "${S}" || die
		default
		cros-rustc_setup_portage_dirs
		return
	fi

	use rust_cros_llvm && _cros-rustc_unpack_llvm_sources
	local dirs=( "${CROS_RUSTC_BUILD_DIR}" "${CROS_RUSTC_SRC_DIR}" )
	if [[ -e "${CROS_RUSTC_SRC_DIR}" || -e "${CROS_RUSTC_BUILD_DIR}" ]]; then
		einfo "Removing old source/build directories..."
		rm -rf "${dirs[@]}"
	fi

	# Disable warnings about 755 only applying to the deepest directory;
	# that's fine.
	# shellcheck disable=SC2174
	mkdir -p -m 755 "${dirs[@]}"
	(cd "${CROS_RUSTC_SRC_DIR}" && default)

	cros-rustc_setup_portage_dirs
}

cros-rustc_llvm-description() {
	if use rust_cros_llvm; then
		# shellcheck disable=SC2154 # defined by cros-rustc-directories
		git -C "${CROS_RUSTC_LLVM_SRC_DIR}" rev-parse HEAD || die
	else
		echo "default"
	fi
}

_cros-rustc_apply_llvm_patches() {
	S="${CROS_RUSTC_LLVM_SRC_DIR}" prepare_patches
}

cros-rustc_src_prepare() {
	if [[ -n "${CROS_RUSTC_BUILD_RAW_SOURCES}" ]]; then
		einfo "Synchronizing bootstrap compiler caches ..."
		cp -avu "${_CROS_RUSTC_RAW_SOURCES_ROOT}/build/cache" "${CROS_RUSTC_BUILD_DIR}" || die
	elif use rust_cros_llvm; then
		einfo "Applying LLVM patches..."
		_cros-rustc_apply_llvm_patches
	fi

	einfo "Applying Rust patches..."
	# Copy "unknown" vendor targets to create cros_sdk target triple
	# variants as referred to in rust-add-cros-targets.patch and
	# RUSTC_TARGET_TRIPLES. armv7a is treated specially because the cros
	# toolchain differs in more than just the vendor part of the target
	# triple. The arch is armv7a in cros versus armv7.
	pushd compiler/rustc_target/src/spec || die
	sed -e 's:"unknown":"pc":g' x86_64_unknown_linux_gnu.rs >x86_64_pc_linux_gnu.rs || die
	sed -e 's:"unknown":"cros":g' x86_64_unknown_linux_gnu.rs >x86_64_cros_linux_gnu.rs || die
	sed -e 's:"unknown":"cros":g' armv7_unknown_linux_gnueabihf.rs >armv7a_cros_linux_gnueabihf.rs || die
	sed -e 's:"unknown":"cros":g' aarch64_unknown_linux_gnu.rs >aarch64_cros_linux_gnu.rs || die
	popd || die

	#sed -e 's:#include <stdlib.h>:void abort(void);:g' -i "${ECONF_SOURCE:-.}"/src/llvm-project/compiler-rt/lib/builtins/int_util.c
	# The miri tool is built because of 'extended = true' in
	# cros-config.toml, but the build is busted. See the upstream issue:
	# [https://github.com/rust- lang/rust/issues/56576]. Because miri isn't
	# installed or needed, this sed script eradicates the command that
	# builds it during the bootstrap script.
	pushd src/bootstrap || die
	sed -i 's@tool::Miri,@@g' builder.rs
	popd || die

	# For the rustc_llvm module, the build will link with -nodefaultlibs and
	# manually choose the std C++ library. For x86_64 Linux, the build
	# script always chooses libstdc++ which will not work if LLVM was built
	# with USE="default-libcxx". This snippet changes that choice to libc++
	# in the case that clang++ defaults to libc++.
	if "${CXX}" -### -x c++ - < /dev/null 2>&1 | grep -q -e '-lc++'; then
		sed -i 's:"stdc++":"c++":g' compiler/rustc_llvm/build.rs || die
	fi

	default

	touch "${_CROS_RUSTC_PREPARED_STAMP}"
	einfo "Rust patch application completed successfully."
}

cros-rustc_src_configure() {
	tc-export CC PKG_CONFIG

	if use rust_cros_llvm; then
		einfo "Symlinking CrOS LLVM"
		local rust_llvm="src/llvm-project"
		rm -rf "${rust_llvm}"
		ln -s "${CROS_RUSTC_LLVM_SRC_DIR}" "${rust_llvm}"
	fi

	# If FEATURES=ccache is set, we can cache LLVM builds. We could set this to
	# true unconditionally, but invoking `ccache` to just have it `exec` the
	# compiler costs ~10secs of wall time on rust-host builds. No point in
	# wasting the cycles.
	local use_ccache=false
	[[ -z "${CCACHE_DISABLE:-}" ]] && use_ccache=true

	local targets=""
	local tt
	# These variables are defined by users of this eclass; their use here is safe.
	# shellcheck disable=SC2154
	for tt in "${RUSTC_TARGET_TRIPLES[@]}" "${RUSTC_BARE_TARGET_TRIPLES[@]}" ; do
		targets+="\"${tt}\", "
	done

	local bootstrap_compiler_info
	local llvm_options
	local rust_options
	local tools
	local llvm_version=$(cros-rustc_llvm-description)

	if [[ -z "${CROS_RUSTC_BUILD_RAW_SOURCES}" ]]; then
		read -r -d '' bootstrap_compiler_info <<- EOF
			cargo = "/opt/rust-bootstrap-${BOOTSTRAP_VERSION}/bin/cargo"
			rustc = "/opt/rust-bootstrap-${BOOTSTRAP_VERSION}/bin/rustc"
		EOF
	fi

	read -r -d '' tools <<- EOF
		tools = ["cargo", "rustfmt", "clippy", "cargofmt", "rustdoc"]
	EOF

	if use rust_profile_llvm_generate || use rust_profile_frontend_generate; then
		ewarn 'This build is instrumented; please only use it to generate profiles.'
		read -r -d '' tools <<- EOF
			# This is an instrumented build, only meant to generate profiles, so we don't need the other tools.
			tools = ["cargo"]
		EOF
	fi

	local llvm_use_pgo_file="${CROS_RUSTC_SRC_DIR}/rust-pgo-${PV}${PROFDATA_SUFFIX}-llvm.profdata"
	local frontend_use_pgo_file="${CROS_RUSTC_SRC_DIR}/rust-pgo-${PV}${PROFDATA_SUFFIX}-frontend.profdata"
	if use rust_profile_llvm_use_local; then
		llvm_use_pgo_file="${FILESDIR}/llvm.profdata"
	fi

	if use rust_profile_frontend_use_local; then
		frontend_use_pgo_file="${FILESDIR}/frontend.profdata"
	fi

	# Either of the instrumented builds will apparently build an instrumented
	# stage 1 compiler, and then use it to build an instrumented stage 2 compiler.
	if use rust_profile_llvm_generate; then
		read -r -d '' llvm_options <<- EOF
			# Without the -vp-static-alloc=false option, we get
			# LLVM Profile Warning: Unable to track new values: Running out of static counters.
			# Alternatively we could use -vp-counters-per-site=2
			# The advantage of using one over the other is unclear.
			cflags = "-fprofile-generate=${CROS_RUSTC_PGO_LOCAL_BASE}/llvm-profraw -mllvm -vp-static-alloc=false"
			cxxflags = "-fprofile-generate=${CROS_RUSTC_PGO_LOCAL_BASE}/llvm-profraw -mllvm -vp-static-alloc=false"
			link-shared = true
		EOF
	fi

	if use rust_profile_frontend_generate; then
		read -r -d '' llvm_options <<- EOF
			# Without the -vp-static-alloc=false option, we get
			# LLVM Profile Warning: Unable to track new values: Running out of static counters.
			# Alternatively we could use -vp-static-alloc=false.
			cflags = "-mllvm -vp-static-alloc=false"
			cxxflags = "-mllvm -vp-static-alloc=false"
		EOF
		read -r -d '' rust_options <<- EOF
			profile-generate = "${CROS_RUSTC_PGO_LOCAL_BASE}/frontend-profraw"
		EOF
	fi

	if use rust_profile_llvm_use || use rust_profile_llvm_use_local; then
		[[ -f "${llvm_use_pgo_file}" ]] || die "No LLVM profdata file"
		read -r -d '' llvm_options <<- EOF
			cflags = "-fprofile-use=${llvm_use_pgo_file}"
			cxxflags = "-fprofile-use=${llvm_use_pgo_file}"
		EOF
	fi

	if use rust_profile_frontend_use || use rust_profile_frontend_use_local; then
		[[ -f "${frontend_use_pgo_file}" ]] || die "No frontend profdata file"
		read -r -d '' rust_options <<- EOF
			profile-use = "${frontend_use_pgo_file}"
		EOF
	fi

	local config=cros-config.toml
	cat > "${config}" <<- EOF
		[build]
		# rust-bootstrap has 'host == x86_64-unknown-linux-gnu', but we
		# want our rustc to be built for CrOS' host triple.
		build = "x86_64-pc-linux-gnu"
		host = ["${CHOST}"]
		target = [${targets}]
		docs = false
		submodules = false
		python = "${EPYTHON}"
		vendor = true
		extended = true
		${tools}
		sanitizers = true
		profiler = true
		build-dir = "${CROS_RUSTC_BUILD_DIR}"
		${bootstrap_compiler_info}

		[llvm]
		ccache = ${use_ccache}
		ninja = true
		experimental-targets = ""
		targets = "AArch64;ARM;X86"
		static-libstdcpp = false
		${llvm_options}

		[install]
		prefix = "${ED}usr"
		libdir = "$(get_libdir)"
		mandir = "share/man"

		[rust]
		default-linker = "${CBUILD}-clang"
		description = "Run /usr/bin/rust-toolchain-version for more detail"
		channel = "nightly"
		# b/271569975: codegen-units feed into cargo's 'profile' for
		# libraries. Differing 'profile's lead to incompatible build
		# artifacts (since cargo's 'profile' generally consists of
		# things like whether the build is debug/release/etc). We need
		# _some_ consistent value here.
		#
		# Pick 32 because that's what we've been shipping from the SDK
		# builder for a while.
		codegen-units = 32
		llvm-libunwind = 'in-tree'
		codegen-tests = false
		new-symbol-mangling = true
		lto = "thin-local"
		${rust_options}
	EOF

	# Ensure that CHOST always has target defs for cc/cxx/linker.
	local extra_target_triples=( "${CHOST}" )
	for tt in "${RUSTC_TARGET_TRIPLES[@]}"; do
		if [[ "${tt}" == "${CHOST}" ]]; then
			extra_target_triples=()
			break
		fi
	done

	for tt in "${extra_target_triples[@]}" "${RUSTC_TARGET_TRIPLES[@]}" ; do
		cat >> "${config}" <<- EOF
			[target."${tt}"]
			cc = "${tt}-clang"
			cxx = "${tt}-clang++"
			linker = "${tt}-clang++"
		EOF
	done
}

cros-rustc_src_compile() {
	${EPYTHON} x.py build --stage 2 --config cros-config.toml "$@" || die

	local llvm_version=$(cros-rustc_llvm-description)
	local version_filename="${CROS_RUSTC_BUILD_DIR}/host/stage2/bin/rust-toolchain-version"
	local extra_text=
	if use rust_profile_llvm_generate || use rust_profile_frontend_generate; then
		extra_text=' (instrumented build; please only use to generate profiles)'
	fi
	cat > "${version_filename}" <<- EOF
		#!/usr/bin/env bash
		echo "${PVR} (with LLVM ${llvm_version})${extra_text}"
	EOF
	chmod +x "${version_filename}"

	# Since we always build for stage2, we're guaranteed that stage1 exists
	# at this point.
	touch "${_CROS_RUSTC_STAGE1_EXISTS_STAMP}"
}
fi
