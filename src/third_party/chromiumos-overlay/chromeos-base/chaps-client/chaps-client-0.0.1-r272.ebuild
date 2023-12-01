# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

CROS_WORKON_COMMIT="e687d49261f807d96ce5b9d8f1bfa8f184aa5bbd"
CROS_WORKON_TREE=("5f52f55a4678653b15e0126bf489a8e105f32768" "b69a75bb85d9791628e0b0a139cc1a33cf27f0b7" "f91b6afd5f2ae04ee9a2c19109a3a4a36f7659e6")
CROS_WORKON_INCREMENTAL_BUILD=1
CROS_WORKON_LOCALNAME="platform2"
CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_OUTOFTREE_BUILD=1
CROS_WORKON_SUBTREE="common-mk chaps .gn"

PLATFORM_SUBDIR="chaps/client"

inherit cros-workon platform

DESCRIPTION="chaps D-Bus client library for Chromium OS"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/chaps/client/"

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

src_install() {
	platform_src_install

	# Install D-Bus client library.
	platform_install_dbus_client_lib "chaps"
}
