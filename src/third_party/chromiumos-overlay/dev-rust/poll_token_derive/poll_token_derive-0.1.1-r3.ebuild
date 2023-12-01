# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

CROS_WORKON_COMMIT="86ce845e172a01b2aba5450f4b5a36d4add91ac5"
CROS_WORKON_TREE="8da6d7dd34a1a3b0b5141e6c49cf25268b1b6a1b"
CROS_RUST_SUBDIR="libchromeos-rs/src/deprecated/poll_token_derive"

CROS_WORKON_INCREMENTAL_BUILD=1
CROS_WORKON_LOCALNAME="../platform2"
CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_SUBTREE="${CROS_RUST_SUBDIR}"

inherit cros-workon cros-rust

DESCRIPTION='Procedural macro for automatically deriving PollToken.'
HOMEPAGE='https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/libchromeos-rs/src/deprecated/poll_token_derive'

LICENSE="BSD-Google"
KEYWORDS="*"

DEPEND="dev-rust/third-party-crates-src:="
RDEPEND="${DEPEND}"
