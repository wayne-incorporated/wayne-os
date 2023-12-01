# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

# Remove windows dependencies.
CROS_WORKON_COMMIT="9b9d131bd8f1d1eac321320f5a2ac3ce5d11fa81"
CROS_WORKON_TREE=("3173ae62bab9e9d18e755d8b4cfb8cf12aa97e92" "029fcfcb0b1b280070db3efa1aef526c226da4e6")
CROS_RUST_REMOVE_TARGET_CFG=1

CROS_WORKON_LOCALNAME="platform/crosvm"
CROS_WORKON_PROJECT="chromiumos/platform/crosvm"
CROS_WORKON_EGIT_BRANCH="chromeos"
CROS_WORKON_INCREMENTAL_BUILD=1
CROS_RUST_SUBDIR="base"
CROS_WORKON_SUBDIRS_TO_COPY=("${CROS_RUST_SUBDIR}" .cargo)
CROS_WORKON_SUBTREE="${CROS_WORKON_SUBDIRS_TO_COPY[*]}"

# The version of this crate is pinned. See b/229016539 for details.
CROS_WORKON_MANUAL_UPREV="1"

inherit cros-workon cros-rust

DESCRIPTION="Small system utility modules for usage by other modules."
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform/crosvm/+/HEAD/base"

LICENSE="BSD-Google"
KEYWORDS="*"
IUSE="test"

# ebuilds that install executables, import crosvm-base, and use the libcap
# functionality need to RDEPEND on libcap
#
# The first group of DEPENDs is for base_event_token_derive.
DEPEND="
	dev-rust/third-party-crates-src:=
	dev-rust/data_model:=
	dev-rust/minijail:=
	dev-rust/sync:=
	media-sound/audio_streams:=
	sys-libs/libcap:=
"
# (crbug.com/1182669): build-time only deps need to be in RDEPEND so they are pulled in when
# installing binpkgs since the full source tree is required to use the crate.
RDEPEND="${DEPEND}"

src_unpack() {
	cros-workon_src_unpack
	if [ ! -e "${S}/${PN}" ]; then
		(cd "${S}" && ln -s "./${CROS_RUST_SUBDIR}" "./${PN}") || die
	fi
	S+="/${PN}"

	cros-rust_src_unpack
}

src_prepare() {
	sed -i 's/name = "base"/name = "'"${PN}"'"/g' "${S}/Cargo.toml"
	cros-rust_src_prepare

	# Use the ChromeOS copy of base instead of the crosvm copy. (For tests folder)
	# Note the trailing slash due to ${S} being a symlink.
	find "${S}/" -iname '*.rs' -type f -exec \
		sed -i -e 's/^use base/use crosvm_base/g' \
			-e 's/\([^[:alnum:]_]\)base::/\1crosvm_base::/g' -- {} +
}

src_test() {
	local skip_tests=()

	(
		cd base_event_token_derive || die
		cros-rust_get_host_test_executables
		cros-rust_src_test
	)

	# If syslog isn't available, skip the tests.
	[[ -S /dev/log ]] || skip_tests+=(--skip "syslog::tests")

	# Non direct exec architectures fail with:
	#   Could not open '/lib/ld-linux-aarch64.so.1': No such file or directory
	CROS_RUST_TEST_DIRECT_EXEC_ONLY="yes"
	cros-rust_get_host_test_executables
	cros-rust_src_test -- --test-threads=1 "${skip_tests[@]}"
}

src_install() {
	(
		cd base_event_token_derive || die
		cros-rust_publish base_event_token_derive "$(cros-rust_get_crate_version .)"
	)

	cros-rust_src_install
}

pkg_preinst() {
	cros-rust_pkg_preinst base_event_token_derive
	cros-rust_pkg_preinst
}

pkg_postinst() {
	cros-rust_pkg_postinst base_event_token_derive
	cros-rust_pkg_postinst
}

pkg_prerm() {
	cros-rust_pkg_prerm base_event_token_derive
	cros-rust_pkg_prerm
}
