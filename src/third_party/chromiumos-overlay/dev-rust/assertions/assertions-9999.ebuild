# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

# Deprecated: Use crates.io/crates/static_assertions instead.

EAPI=7

CROS_WORKON_LOCALNAME="../platform/crosvm"
CROS_WORKON_PROJECT="chromiumos/platform/crosvm"
CROS_WORKON_EGIT_BRANCH="chromeos"
CROS_WORKON_OUTOFTREE_BUILD=1
CROS_WORKON_INCREMENTAL_BUILD=1
CROS_RUST_SUBDIR="common/assertions"
CROS_WORKON_SUBDIRS_TO_COPY=("/")
CROS_WORKON_SUBTREE="${CROS_WORKON_SUBDIRS_TO_COPY[*]}"

# This crate is only used by sys_util and data_model, which are pinned to a fixed revision of
# crosvm. See b/229016539 for details.
CROS_WORKON_MANUAL_UPREV="1"

inherit cros-workon cros-rust

DESCRIPTION="Crates for compile-time assertion macro."
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform/crosvm/+/HEAD/assertions"

LICENSE="BSD-Google"
KEYWORDS="~*"
IUSE="test"

RDEPEND="!!<=dev-rust/assertions-0.1.0-r3"
