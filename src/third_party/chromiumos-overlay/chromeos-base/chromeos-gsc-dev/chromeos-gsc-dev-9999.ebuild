# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE.makefile file.

EAPI="7"

CROS_WORKON_PROJECT=("chromiumos/platform/ec")
CROS_WORKON_LOCALNAME=("platform/gsc-utils")
CROS_WORKON_DESTDIR=("${S}/platform/gsc-utils")
CROS_WORKON_EGIT_BRANCH=("gsc_utils")

inherit cros-workon toolchain-funcs cros-sanitizers

DESCRIPTION="Google Security Chip handling utilities"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform/ec/+/refs/heads/gsc_utils"

LICENSE="BSD-Google"
KEYWORDS="~*"
IUSE=""

COMMON_DEPEND="
	dev-libs/openssl:0=
	virtual/libusb:1=
"

RDEPEND="
	!<chromeos-base/chromeos-cr50-dev-0.0.2
	${COMMON_DEPEND}
"

DEPEND="${COMMON_DEPEND}"

src_unpack() {
	cros-workon_src_unpack
	S+="/platform/gsc-utils"
}

set_build_env() {
	cros_use_gcc

	tc-export CC BUILD_CC PKG_CONFIG
	export HOSTCC=${CC}
	export BUILDCC=${BUILD_CC}
}

src_compile() {
	set_build_env

	export BOARD=cr50

	emake -C extra/usb_updater clean
	emake -C extra/usb_updater gsctool
}

src_configure() {
	sanitizers-setup-env
	default
}

src_install() {
	dosbin "extra/usb_updater/gsctool"
	dosym "gsctool" "/usr/sbin/usb_updater"
}
