# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

inherit cros-constants

CROS_WORKON_LOCALNAME=(
	"platform2"
	"platform/pinweaver"
)
CROS_WORKON_PROJECT=(
	"chromiumos/platform2"
	"chromiumos/platform/pinweaver"
)
CROS_WORKON_OPTIONAL_CHECKOUT=(
	"true"
	"true"
)
CROS_WORKON_DESTDIR=(
	"${S}/platform2"
	"${S}/platform2/pinweaver"
)
# TODO(crbug.com/809389): Avoid directly including headers from other packages.
CROS_WORKON_SUBTREE=(
	"common-mk .gn"
	""
)
PLATFORM_SUBDIR="pinweaver"

inherit cros-workon platform

DESCRIPTION="PinWeaver code that can be used across implementation platforms."
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform/pinweaver/+/main/"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="~*"

RDEPEND=""

DEPEND="${RDEPEND}"

src_install() {
	platform_src_install

	dolib.a "${OUT}"/libpinweaver.a

	insinto /usr/include/pinweaver
	doins eal/tpm_storage/pinweaver_eal_types.h
	doins pinweaver.h
	doins pinweaver_eal.h
	doins pinweaver_types.h
}
