# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_COMMIT="e687d49261f807d96ce5b9d8f1bfa8f184aa5bbd"
CROS_WORKON_TREE=("5f52f55a4678653b15e0126bf489a8e105f32768" "a97cc2b9804da119c7c09210be9cc9b806381f56" "f91b6afd5f2ae04ee9a2c19109a3a4a36f7659e6")
CROS_WORKON_INCREMENTAL_BUILD=1
CROS_WORKON_LOCALNAME="platform2"
CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_OUTOFTREE_BUILD=1
CROS_WORKON_SUBTREE="common-mk cryptohome .gn"

PLATFORM_SUBDIR="cryptohome/client"

inherit cros-workon platform

DESCRIPTION="Cryptohome D-Bus client library for Chromium OS"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/cryptohome"

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

# r3700 because we moved the dbus headers for UserDataAuth from cryptohome into
# cryptohome-client in that version.
RDEPEND="
	!<chromeos-base/cryptohome-0.0.1-r3700
"

src_install() {
	platform_src_install

	# Install D-Bus client library.
	platform_install_dbus_client_lib "user_data_auth"
}
