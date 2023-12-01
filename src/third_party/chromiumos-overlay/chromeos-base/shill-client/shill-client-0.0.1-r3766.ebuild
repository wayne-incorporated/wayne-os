# Copyright 2015 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_COMMIT="a0f68260b415e9e83aedced330c264ffbb768ca7"
CROS_WORKON_TREE=("5f52f55a4678653b15e0126bf489a8e105f32768" "23ecb8d5aa084a2763d1f25f0c9a1836d5245989" "f91b6afd5f2ae04ee9a2c19109a3a4a36f7659e6")
CROS_WORKON_INCREMENTAL_BUILD=1
CROS_WORKON_OUTOFTREE_BUILD=1
CROS_WORKON_LOCALNAME="platform2"
CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_SUBTREE="common-mk shill .gn"

PLATFORM_NATIVE_TEST="yes"
PLATFORM_SUBDIR="shill/client"

inherit cros-workon platform

DESCRIPTION="Shill DBus client library for Chromium OS"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/shill/"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"

BDEPEND="
	chromeos-base/chromeos-dbus-bindings
"

# Workaround to rebuild this package on the chromeos-dbus-bindings update.
# Please find the comment in chromeos-dbus-bindings for its background.
DEPEND="
	chromeos-base/chromeos-dbus-bindings:=
"

RDEPEND="
	!<chromeos-base/shill-0.0.2
"

src_install() {
	platform_src_install

	# Install DBus client library.
	platform_install_dbus_client_lib "shill"
}
