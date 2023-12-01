# Copyright 2015 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_COMMIT="6b581a826e1131010c16eb83fa4b0a0f3dc71215"
CROS_WORKON_TREE=("5f52f55a4678653b15e0126bf489a8e105f32768" "6d99312395b69f3ace70f6cd5b78d1887b148579" "f91b6afd5f2ae04ee9a2c19109a3a4a36f7659e6")
CROS_WORKON_INCREMENTAL_BUILD=1
CROS_WORKON_LOCALNAME="platform2"
CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_OUTOFTREE_BUILD=1
CROS_WORKON_SUBTREE="common-mk login_manager .gn"

PLATFORM_NATIVE_TEST="yes"
PLATFORM_SUBDIR="login_manager/session_manager-client"

inherit cros-workon platform

DESCRIPTION="Session manager (chromeos-login) DBus client library for Chromium OS"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/login_manager/"

LICENSE="BSD-Google"
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
	!<chromeos-base/chromeos-login-0.0.2
"

src_install() {
	platform_src_install

	# Install DBus client library.
	platform_install_dbus_client_lib "session_manager"
}
