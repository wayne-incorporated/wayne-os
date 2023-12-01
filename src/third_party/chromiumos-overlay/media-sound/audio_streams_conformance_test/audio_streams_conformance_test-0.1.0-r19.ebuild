# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI="7"

CROS_WORKON_COMMIT="c06bff8c3fa6ce066e9f6f604735bd86f52981ee"
CROS_WORKON_TREE=("473980ec10874aee75c0482146e48e964da9013c" "a29c68ff44264bf89ad73ad5e1fad81aac9b472a")
CROS_WORKON_LOCALNAME="../platform/crosvm"
CROS_WORKON_PROJECT="chromiumos/platform/crosvm"
CROS_WORKON_INCREMENTAL_BUILD=1
CROS_RUST_SUBDIR="tools/audio_streams_conformance_test"
CROS_WORKON_SUBDIRS_TO_COPY=("${CROS_RUST_SUBDIR}" .cargo)
CROS_WORKON_SUBTREE="${CROS_WORKON_SUBDIRS_TO_COPY[*]}"

inherit cros-workon cros-rust

DESCRIPTION="A Tool to verify the implementation correctness of audio_streams API."
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform/crosvm/+/refs/heads/main/tools/audio_streams_conformance_test"

LICENSE="BSD-Google"
KEYWORDS="*"
IUSE="test"

DEPEND="
	dev-rust/third-party-crates-src:=
	media-sound/audio_streams:=
	media-sound/cras-client:=
	dev-rust/cros_async:=
"

src_compile() {
	local features=(
		chromeos
	)

	ecargo_build -v \
		--features="${features[*]}" ||
		die "cargo build failed"
}


src_install() {
	dobin "$(cros-rust_get_build_dir)/audio_streams_conformance_test"
}
