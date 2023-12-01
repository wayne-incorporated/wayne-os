# Copyright 2023 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

# This ebuild only cares about its own FILESDIR and ebuild file, so it tracks
# the canonical empty project.
CROS_WORKON_COMMIT="d2d95e8af89939f893b1443135497c1f5572aebc"
CROS_WORKON_TREE="776139a53bc86333de8672a51ed7879e75909ac9"
CROS_WORKON_PROJECT="chromiumos/infra/build/empty-project"
CROS_WORKON_LOCALNAME="../platform/empty-project"

inherit cros-workon

DESCRIPTION="List of packages needed in the SDK's rust registry for the cargo workflow."
HOMEPAGE="https://dev.chromium.org/"

LICENSE="metapackage"
SLOT="0"
KEYWORDS="*"

# Note this should primarily be dependencies with a patch.crates-io modifier
# referencing the chroot's cros_rust_registry.
RDEPEND="
	chromeos-base/crosvm-base
	dev-rust/cros_async
	dev-rust/data_model
	dev-rust/io_uring
	dev-rust/serde_keyvalue
	dev-rust/serde_keyvalue_derive
	dev-rust/sync
	dev-rust/third-party-crates-src
	media-sound/audio_streams
"
