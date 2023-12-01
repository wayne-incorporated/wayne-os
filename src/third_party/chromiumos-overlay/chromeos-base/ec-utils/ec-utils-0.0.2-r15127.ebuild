# Copyright 2012 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7
CROS_WORKON_COMMIT="a9619362103a395a637a2617489effb11814e011"
CROS_WORKON_TREE="282a7ce466d66d8061fc266dbd5cffff33f92f1c"
CROS_WORKON_PROJECT="chromiumos/platform/ec"
CROS_WORKON_LOCALNAME="platform/ec"

# This ebuild is upreved via PuPR, so disable the normal uprev process for
# cros-workon ebuilds.
#
# To uprev manually, run:
#    cros_mark_as_stable --force --overlay-type private --packages \
#     chromeos-base/ec-utils commit
CROS_WORKON_MANUAL_UPREV="1"

inherit cros-workon user

DESCRIPTION="Chrome OS EC Utility"

HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform/ec/"
SRC_URI=""

LICENSE="BSD-Google"
KEYWORDS="*"
IUSE="static -updater_utils"
IUSE="${IUSE} cros_host +cros_ec_utils"

COMMON_DEPEND="
	chromeos-base/libec:=
	dev-embedded/libftdi:=
	dev-libs/openssl:0=
	sys-libs/zlib:=
	virtual/libusb:1="

# b/274791539: gtest is required because libec includes a libchrome header that
# requires gtest to be installed when building.
DEPEND="${COMMON_DEPEND}
	dev-cpp/gtest
"
RDEPEND="${COMMON_DEPEND}"

pkg_preinst() {
	enewgroup "dialout"
}

src_compile_cros_ec_utils() {
	BOARD=host emake utils-host CC="${CC}"
}

src_compile() {
	tc-export AR CC PKG_CONFIG RANLIB
	# In platform/ec Makefile, it uses "CC" to specify target chipset and
	# "HOSTCC" to compile the utility program because it assumes developers
	# want to run the utility from same host (build machine).
	# In this ebuild file, we only build utility
	# and we may want to build it so it can
	# be executed on target devices (i.e., arm/x86/amd64), not the build
	# host (BUILDCC, amd64). So we need to override HOSTCC by target "CC".
	export HOSTCC="${CC} $(usex static '-static' '')"

	# b/247791129: EC expects HOST_PKG_CONFIG to be the pkg-config targeting the
	# platform that the EC is running on top of (e.g., the Chromebook's AP).
	# That platform corresponds to the ChromeOS "$BOARD" and the pkg-config for
	# the "$BOARD" being built is specified by tc-getPKG_CONFIG.
	export HOST_PKG_CONFIG
	HOST_PKG_CONFIG=$(tc-getPKG_CONFIG)

	# EC expects BUILD_PKG_CONFIG to be the pkg-config targeting the build
	# machine (the machine doing the compilation).
	export BUILD_PKG_CONFIG
	BUILD_PKG_CONFIG=$(tc-getBUILD_PKG_CONFIG)

	# Build Chromium EC utilities.
	use cros_ec_utils && src_compile_cros_ec_utils
}

src_install_cros_ec_utils() {
	if use cros_host; then
		dobin "build/host/util/cbi-util"
	else
		dosbin "build/host/util/ectool"
	fi
}

src_install() {
	# Install Chromium EC utilities.
	use cros_ec_utils && src_install_cros_ec_utils
}

pkg_postinst() {
	if ! $(id -Gn "$(logname)" | grep -qw "dialout") ; then
		usermod -a -G "dialout" "$(logname)"
		einfo "A new group, dialout is added." \
			"Please re-login to apply this change."
	fi
}
