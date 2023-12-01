# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7
CROS_WORKON_INCREMENTAL_BUILD=1
CROS_WORKON_LOCALNAME="platform2"
CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_OUTOFTREE_BUILD=1
CROS_WORKON_SUBTREE="private_computing common-mk .gn"

PLATFORM_SUBDIR="private_computing"

inherit cros-workon platform user tmpfiles

DESCRIPTION="A daemon that saves and retrieves device active status with preserved file."
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/private_computing/"
LICENSE="BSD-Google"
KEYWORDS="~*"

IUSE=""
COMMON_DEPEND="
	chromeos-base/minijail
	dev-libs/protobuf
"

RDEPEND="${COMMON_DEPEND}"
DEPEND="${COMMON_DEPEND}
	chromeos-base/system_api:=
	sys-apps/dbus:=
"

src_install() {
	platform_src_install
	dotmpfiles tmpfiles.d/private_computing.conf
}

platform_pkg_test() {
	platform test_all
}

pkg_preinst() {
	enewuser "private_computing"
	enewgroup "private_computing"
}
