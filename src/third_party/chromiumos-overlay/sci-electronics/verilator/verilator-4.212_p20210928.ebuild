# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit autotools

DESCRIPTION="The fastest Verilog/SystemVerilog simulator"
HOMEPAGE="https://www.veripool.org/verilator/"

GIT_REV="20af8a36a77d2b11b0522b214ba95047c16c887b"
SRC_URI="https://github.com/verilator/verilator/archive/${GIT_REV}.tar.gz -> ${P}.tar.gz"

LICENSE="LGPL-3"
SLOT="0"
KEYWORDS="*"

IUSE="+systemc test"
RESTRICT="!test? ( test )"

DEPEND="
	systemc? ( sci-electronics/systemc )
"
RDEPEND="${DEPEND}"
BDEPEND="
	test? ( sys-apps/grep[pcre] )
"

S="${WORKDIR}/verilator-${GIT_REV}"

src_prepare() {
	eautoconf
	default
}

src_compile() {
	local emake_args=()
	if use systemc; then
		get_systemc_variable() {
			local pkg_config="$(tc-getPKG_CONFIG)"
			local result="$(${pkg_config} systemc --variable=${1})"
			if [[ -z "${result}" ]]; then
				die "'${1}' variable not found in SystemC package with ${pkg_config}"
			fi
			echo "${result}"
		}
		# These variables simplify using Verilator with SystemC. They are built-in only
		# if set during compilation -- neither autoconf nor configure set them properly.
		emake_args+=(
			"SYSTEMC_INCLUDE=$(get_systemc_variable includedir)"
			"SYSTEMC_LIBDIR=$(get_systemc_variable libarchdir)"
		)
	fi
	emake ${emake_args[@]}
}

# The `default_src_test` doesn't work because `make test -n` fails.
src_test() {
	if use systemc; then
		# Check if SYSTEMC variables are set. Setting these is error-prone.
		[[ -n "$(./bin/verilator --getenv SYSTEMC_INCLUDE)" ]] || die
		[[ -n "$(./bin/verilator --getenv SYSTEMC_LIBDIR)" ]] || die
	fi

	emake test
}
