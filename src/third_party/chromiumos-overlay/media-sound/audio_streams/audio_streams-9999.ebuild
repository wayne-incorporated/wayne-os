# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

CROS_RUST_SUBDIR="common/audio_streams"

CROS_WORKON_LOCALNAME="../platform/crosvm"
CROS_WORKON_PROJECT="chromiumos/platform/crosvm"
CROS_WORKON_EGIT_BRANCH="chromeos"
CROS_WORKON_INCREMENTAL_BUILD=1
CROS_WORKON_SUBTREE="${CROS_RUST_SUBDIR}"
CROS_WORKON_SUBDIRS_TO_COPY="${CROS_RUST_SUBDIR}"

inherit cros-workon cros-rust

DESCRIPTION="Crate provides a basic interface for playing audio."
HOMEPAGE="https://chromium.googlesource.com/chromiumos/third_party/adhd/+/HEAD/audio_streams"

LICENSE="BSD-Google"
KEYWORDS="~*"
IUSE="test"

DEPEND="
	dev-rust/third-party-crates-src:=
"
# (crbug.com/1182669): build-time only deps need to be in RDEPEND so they are pulled in when
# installing binpkgs since the full source tree is required to use the crate.
RDEPEND="${DEPEND}
	!<=media-sound/audio_streams-0.1.0-r49
"

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
