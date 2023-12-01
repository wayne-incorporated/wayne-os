# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_COMMIT="bb1ba9d554fcb89d36f2f0afd44cc5efa2de8e4c"
CROS_WORKON_TREE="555899a7d9315dbe6decbcfd77961e71d49f37aa"
CROS_RUST_SUBDIR="common/balloon_control"

CROS_WORKON_LOCALNAME="../platform/crosvm"
CROS_WORKON_PROJECT="chromiumos/platform/crosvm"
CROS_WORKON_EGIT_BRANCH="chromeos"
CROS_WORKON_INCREMENTAL_BUILD=1
CROS_WORKON_SUBTREE="${CROS_RUST_SUBDIR}"
CROS_WORKON_SUBDIRS_TO_COPY="${CROS_RUST_SUBDIR}"

inherit cros-workon cros-rust

DESCRIPTION="APIs to allow external control of a virtio balloon device"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform/crosvm/+/HEAD/common/balloon_control"

LICENSE="BSD-Google"
KEYWORDS="*"
IUSE="test"

DEPEND="dev-rust/third-party-crates-src:="
RDEPEND="${DEPEND}"

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
