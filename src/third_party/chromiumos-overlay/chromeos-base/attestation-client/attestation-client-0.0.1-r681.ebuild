# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

CROS_WORKON_COMMIT="5a40186abf3a23ed8707d6cef25112167eabaede"
CROS_WORKON_TREE=("5f52f55a4678653b15e0126bf489a8e105f32768" "87302ba74a8214d7c4c682cdb9fb930652c5ff0d" "9141f838cd358da366d33cdb32c1c08a5aeeb8fa" "f91b6afd5f2ae04ee9a2c19109a3a4a36f7659e6")
CROS_WORKON_INCREMENTAL_BUILD=1
CROS_WORKON_LOCALNAME="platform2"
CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_OUTOFTREE_BUILD=1
CROS_WORKON_SUBTREE="common-mk attestation libhwsec-foundation .gn"

PLATFORM_SUBDIR="attestation/client"

inherit cros-workon platform

DESCRIPTION="Attestation D-Bus client library for Chromium OS"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/attestation/client/"

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
	chromeos-base/system_api:=[fuzzer?]
"

# Note that for RDEPEND, we conflict with attestation package older than
# 0.0.1 because this client is incompatible with daemon older than version
# 0.0.1. We didn't RDEPEND on attestation version 0.0.1 or greater because
# we don't want to create circular dependency in case the package attestation
# depends on some package foo that also depend on this package.
RDEPEND="
	!<chromeos-base/attestation-0.0.1
"

src_install() {
	platform_src_install

	# Install D-Bus client library.
	platform_install_dbus_client_lib "attestation"
}
