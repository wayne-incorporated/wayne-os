# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_COMMIT="7265b6b2f91ac953e943f010cf3c4b9d696bab1b"
CROS_WORKON_TREE="a1b21134fdadc10b1f85b44ff59a5dfe37599b00"
CROS_RUST_SUBDIR="common/p9"

CROS_WORKON_LOCALNAME="../platform/crosvm"
CROS_WORKON_PROJECT="chromiumos/platform/crosvm"
CROS_WORKON_EGIT_BRANCH="chromeos"
CROS_WORKON_INCREMENTAL_BUILD=1
CROS_WORKON_SUBTREE="${CROS_RUST_SUBDIR}"
CROS_WORKON_SUBDIRS_TO_COPY="${CROS_RUST_SUBDIR}"

inherit cros-workon cros-rust

DESCRIPTION="Server implementation of the 9P file system protocol"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/vm_tools/p9/"

LICENSE="BSD-Google"
KEYWORDS="*"
IUSE="test"

DEPEND="
	dev-rust/third-party-crates-src:=
"
# (crbug.com/1182669): build-time only deps need to be in RDEPEND so they are pulled in when
# installing binpkgs since the full source tree is required to use the crate.
RDEPEND="${DEPEND}
	!!<=dev-rust/p9-0.1.0-r14
"

get_crate_version() {
	local crate="$1"
	awk '/^version = / { print $3 }' "${crate}/Cargo.toml" | head -n1 | tr -d '"'
}

pkg_setup() {
	cros-rust_pkg_setup wire_format_derive
	cros-rust_pkg_setup p9
}

src_unpack() {
	# Copy the CROS_RUST_SUBDIR to a new location in the $S dir to make sure cargo will not
	# try to build it as apart of the crosvm workspace.
	cros-workon_src_unpack
	if [ ! -e "${S}/${PN}" ]; then
		(cd "${S}" && ln -s "./${CROS_RUST_SUBDIR}" "./${PN}") || die
	fi
	S+="/${PN}"

	cros-rust_src_unpack
}

src_compile() {
	(
		cd wire_format_derive || die
		ecargo_build
		use test && ecargo_test --no-run
	)

	ecargo_build
	use test && ecargo_test --no-run
}

src_test() {
	(
		cd wire_format_derive || die
		cros-rust_src_test
	)

	cros-rust_src_test
}

src_install() {
	pushd wire_format_derive >/dev/null || die
	local version="$(get_crate_version .)"
	cros-rust_publish wire_format_derive "${version}"
	popd >/dev/null || die

	version="$(get_crate_version .)"
	cros-rust_publish p9 "${version}"
}

pkg_preinst() {
	cros-rust_pkg_preinst wire_format_derive
	cros-rust_pkg_preinst p9
}

pkg_postinst() {
	cros-rust_pkg_postinst wire_format_derive
	cros-rust_pkg_postinst p9
}

pkg_prerm() {
	cros-rust_pkg_prerm wire_format_derive
	cros-rust_pkg_prerm p9
}
