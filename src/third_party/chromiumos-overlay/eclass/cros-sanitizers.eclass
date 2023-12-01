# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

# @ECLASS: cros-sanitizers.eclass
# @MAINTAINER:
# ChromeOS toolchain team <chromeos-toolchain@google.com>
# @DESCRIPTION:
# Ebuild helper functions for sanitizer builds on Chrome OS.

if [[ -z ${_CROS_SANITIZER_ECLASS} ]]; then
_CROS_SANITIZER_ECLASS=1

inherit flag-o-matic toolchain-funcs

IUSE="asan cfi cfi_diag cfi_recover coverage fuzzer msan thinlto tsan ubsan"
REQUIRED_USE="
	cfi? ( thinlto )
	cfi_diag? ( cfi )
	cfi_recover? ( cfi_diag )
"

# @ECLASS-VARIABLE: CROS_SANITIZER_CFI_FEATURES
# @DESCRIPTION:
# Array of cfi features to enable when calling cfi-setup-env.
CROS_SANITIZER_CFI_FEATURES=(
	"derived-cast"
	"icall"
	"vcall"
	"unrelated-cast"
)

# @ECLASS-VARIABLE: CROS_SANITIZER_CFI_IGNORE
# @PRE_INHERIT
# @DESCRIPTION:
# A path to a file to use as the ignore-list for CFI at build time.
# The default is "${FILESDIR}/cfi-ignore.txt"
: "${CROS_SANITIZER_CFI_IGNORE:=}"

# @FUNCTION: sanitizer-add-blocklist
# @DESCRIPTION:
# Add blocklist files to the sanitizer build flags.
sanitizer-add-blocklist() {
	if [[ $# -gt 1 ]]; then
		die "More than one argument passed."
	fi

	# Search blocklist files in source and files directories.
	local files_list=(
		"${FILESDIR}/sanitizer_blocklist.txt"
		"${S}/sanitizer_blocklist.txt"
	)
	# If a sanitizer name is passed, then search ${sanitizer}_blocklist.txt.
	if [[ $# -eq 1 ]]; then
		files_list+=(
			"${FILESDIR}/$1_blocklist.txt"
			"${S}/$1_blocklist.txt"
		)
	fi

	for blocklist_file in "${files_list[@]}"; do
		if [[ -f "${blocklist_file}" ]]; then
			append-flags "-fsanitize-blacklist=${blocklist_file}"
		fi
	done
}

# @FUNCTION: asan-setup-env
# @DESCRIPTION:
# Build a package with address sanitizer flags.
asan-setup-env() {
	use asan || return 0
	if ! tc-is-clang; then
		die "ASAN is only supported for clang"
	fi
	local asan_flags=(
		"-fsanitize=address"
	)
	append-flags "${asan_flags[@]}"
	append-ldflags "${asan_flags[@]}"
	sanitizer-add-blocklist "asan"
}

# @FUNCTION: cfi-setup-env
# @DESCRIPTION:
# Build a package with LTO-based cfi if USE=cfi. Note that if USE=cfi_diag is
# set additional debugging information is printed and if USE=cfi_recover is set
# execution is allowed to continue past a violation.
cfi-setup-env() {
	use cfi || return 0
	local flags=(
		"-fvisibility=default"
	)
	local lflags=()
	if use thinlto ; then
		flags+=( "-flto=thin" )
		lflags+=( "-Wl,--lto-O0" )
	else
		die "LTO is required for CFI"
	fi
	local feature
	for feature in "${CROS_SANITIZER_CFI_FEATURES[@]}"; do
		case "${feature}" in
		"derived-cast" | "icall" | "vcall" | "unrelated-cast")
			flags+=( "-fsanitize=cfi-${feature}" )
			;;
		*)
			die "${feature} is not a supported CFI feature"
			;;
		esac
	done

	local default_ignore="${FILESDIR}/cfi-ignore.txt"
	if [[ -z "${CROS_SANITIZER_CFI_IGNORE}" ]]; then
		# If this isn't set apply the default if it exists.
		if [[ -f "${default_ignore}" ]]; then
			einfo "Applying default CFI ignore list: '${default_ignore}'"
			flags+=( "-fsanitize-ignorelist=${default_ignore}" )
		fi
	elif [[ -f "${CROS_SANITIZER_CFI_IGNORE}" ]] ; then
		flags+=( "-fsanitize-ignorelist=${CROS_SANITIZER_CFI_IGNORE}" )
	else
		die "CFI ignore list '${CROS_SANITIZER_CFI_IGNORE}' not found."
	fi
	use cfi_diag && flags+=( "-fno-sanitize-trap=cfi" )
	use cfi_recover && flags+=( "-fsanitize-recover=cfi" )
	append-flags "${flags[@]}"
	append-ldflags "${flags[@]}" "${lflags[@]}"
}

# @FUNCTION: coverage-setup-env
# @DESCRIPTION:
# Build a package with coverage flags.
coverage-setup-env() {
	use coverage || return 0
	append-flags -fprofile-instr-generate -fcoverage-mapping
	append-ldflags -fprofile-instr-generate -fcoverage-mapping
}

# @FUNCTION: msan-setup-env
# @DESCRIPTION:
# Build a package with memory sanitizer flags.
msan-setup-env() {
	use msan || return 0
	# msan does not work with FORTIFY enabled.
	append-cppflags "-U_FORTIFY_SOURCE"
	append-flags "-fsanitize=memory -fsanitize-memory-track-origins"
	append-ldflags "-fsanitize=memory"
	sanitizer-add-blocklist "msan"
}

# @FUNCTION: tsan-setup-env
# @DESCRIPTION:
# Build a package with thread sanitizer flags.
tsan-setup-env() {
	use tsan || return 0
	append-flags "-fsanitize=thread"
	append-ldflags "-fsanitize=thread"
	sanitizer-add-blocklist "tsan"
}

# @FUNCTION: ubsan-setup-env
# @DESCRIPTION:
# Build a package with undefined behavior sanitizer flags.
ubsan-setup-env() {
	use ubsan || return 0
	# Flags for normal ubsan builds.
	# TODO: Use same flags as fuzzer builds.
	local flags=(
		"-fsanitize=alignment,array-bounds,pointer-overflow,shift"
		"-fsanitize=integer-divide-by-zero,float-divide-by-zero"
		"-fsanitize=signed-integer-overflow,vla-bound"
		"-fno-sanitize=vptr"
		"-fno-sanitize-recover=all"
	)
	# Use different flags for fuzzer ubsan builds.
	if use fuzzer; then
		flags=(
			"-fsanitize=alignment,array-bounds,function,pointer-overflow"
			"-fsanitize=integer-divide-by-zero,float-divide-by-zero"
			"-fsanitize=signed-integer-overflow,shift,vla-bound,vptr"
			"-fno-sanitize-recover=all"
			"-frtti"
		)
	fi
	append-flags "${flags[@]}"
	append-ldflags "${flags[@]}"
	append-cppflags -DCHROMEOS_UBSAN_BUILD
	sanitizer-add-blocklist "ubsan"
}

# @FUNCTION: sanitizers-setup-env
# @DESCRIPTION:
# Build a package with required sanitizer flags.
sanitizers-setup-env() {
	asan-setup-env
	cfi-setup-env
	coverage-setup-env
	if [[ $(type -t fuzzer-setup-env) == "function" ]] ; then
		# Only run this if we've inherited cros-fuzzer.eclass.
		fuzzer-setup-env
	fi
	msan-setup-env
	tsan-setup-env
	ubsan-setup-env
}

# @FUNCTION: cros-rust-setup-sanitizers
# @DESCRIPTION:
# Sets up sanitizer flags for rust.
cros-rust-setup-sanitizers() {
	local rust_san_flags=( "${RUSTFLAGS[@]}" )
	use asan && rust_san_flags+=( -Zsanitizer=address )
	if use cfi ; then
		ewarn "CFI with mixed Rust and C/C++ is not supported by the toolchain team."
		ewarn "(i.e. use at your own risk)."
		rust_san_flags+=( -Zsplit-lto-unit -Clinker-plugin-lto=yes )
	fi
	use lsan && rust_san_flags+=( -Zsanitizer=leak )
	use msan && rust_san_flags+=( -Zsanitizer=memory )
	use tsan && rust_san_flags+=( -Zsanitizer=thread )
	export RUSTFLAGS="${rust_san_flags[*]}"
}

# @FUNCTION: use_sanitizers
# @DESCRIPTION:
# Checks whether sanitizers are being used.
# Also returns a true/false value when passed as arguments.
# Usage: use_sanitizers [trueVal] [falseVal]
use_sanitizers() {
	if use asan || use coverage || use fuzzer || use msan || use tsan || use ubsan; then
		[[ "$#" -eq 2 ]] && echo "$1"
		return 0
	fi

	[[ "$#" -eq 2 ]] && echo "$2"
	return 1
}

fi
