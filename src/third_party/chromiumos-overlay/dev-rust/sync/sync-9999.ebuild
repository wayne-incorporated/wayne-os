# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_RUST_SUBDIR="common/sync"

CROS_WORKON_LOCALNAME="../platform/crosvm"
CROS_WORKON_PROJECT="chromiumos/platform/crosvm"
CROS_WORKON_EGIT_BRANCH="chromeos"
CROS_WORKON_INCREMENTAL_BUILD=1
CROS_WORKON_SUBTREE="${CROS_RUST_SUBDIR}"
CROS_WORKON_SUBDIRS_TO_COPY="${CROS_RUST_SUBDIR}"

# The version of this crate is pinned. See b/229016539 for details.
CROS_WORKON_MANUAL_UPREV="1"

inherit cros-workon cros-rust

DESCRIPTION="Containing a type sync::Mutex which wraps the standard library Mutex and mirrors the same methods"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform/crosvm/+/HEAD/sync"

LICENSE="BSD-Google"
KEYWORDS="~*"
IUSE="test"

RDEPEND="!!<=dev-rust/sync-0.1.0-r6"

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

src_prepare() {
	cros-rust_src_prepare

	# Replace the version in the sources with the ebuild version.
	# ${FILESDIR}/chromeos-version.sh sets the minor version 50 ahead to avoid
	# colliding with the version included by path.
	if [[ "${PV}" != 9999 ]]; then
		sed -i 's/^version = .*$/version = "'"${PV}"'"/g' "${S}/Cargo.toml"
	fi
}
