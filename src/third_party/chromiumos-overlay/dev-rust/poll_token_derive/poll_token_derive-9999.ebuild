# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

CROS_RUST_SUBDIR="libchromeos-rs/src/deprecated/poll_token_derive"

CROS_WORKON_INCREMENTAL_BUILD=1
CROS_WORKON_LOCALNAME="../platform2"
CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_SUBTREE="${CROS_RUST_SUBDIR}"

inherit cros-workon cros-rust

DESCRIPTION='Procedural macro for automatically deriving PollToken.'
HOMEPAGE='https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/libchromeos-rs/src/deprecated/poll_token_derive'

LICENSE="BSD-Google"
KEYWORDS="~*"

DEPEND="dev-rust/third-party-crates-src:="
RDEPEND="${DEPEND}"
