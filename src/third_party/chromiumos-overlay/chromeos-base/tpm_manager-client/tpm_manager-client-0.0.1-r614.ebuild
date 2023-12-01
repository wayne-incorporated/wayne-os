# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="6"

CROS_WORKON_COMMIT="e687d49261f807d96ce5b9d8f1bfa8f184aa5bbd"
CROS_WORKON_TREE=("5f52f55a4678653b15e0126bf489a8e105f32768" "9141f838cd358da366d33cdb32c1c08a5aeeb8fa" "92c52c0f0760bee1324c18e4e1878be5f67b2674" "f91b6afd5f2ae04ee9a2c19109a3a4a36f7659e6")
CROS_WORKON_INCREMENTAL_BUILD=1
CROS_WORKON_LOCALNAME="platform2"
CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_OUTOFTREE_BUILD=1
CROS_WORKON_SUBTREE="common-mk libhwsec-foundation tpm_manager .gn"

PLATFORM_SUBDIR="tpm_manager/client"

inherit cros-workon platform

DESCRIPTION="TPM Manager D-Bus client library for Chromium OS"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/tpm_manager/client/"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE="test tpm tpm2 fuzzer"

BDEPEND="
	chromeos-base/chromeos-dbus-bindings
"

# Workaround to rebuild this package on the chromeos-dbus-bindings update.
# Please find the comment in chromeos-dbus-bindings for its background.
DEPEND="
	chromeos-base/chromeos-dbus-bindings:=
	chromeos-base/system_api:=[fuzzer?]
"

# Note that for RDEPEND, we conflict with tpm_manager package older than
# 0.0.1 because this client is incompatible with daemon older than version
# 0.0.1. We didn't RDEPEND on tpm_manager version 0.0.1 or greater because
# we don't want to create circular dependency in case the package tpm_manager
# depends on some package foo that also depend on this package.
RDEPEND="
	!<chromeos-base/tpm_manager-0.0.1-r2238
	chromeos-base/libbrillo:=
	chromeos-base/system_api:=[fuzzer?]
"

src_install() {
	platform_src_install

	# Install D-Bus client library.
	platform_install_dbus_client_lib "tpm_manager"

	dobin "${OUT}"/tpm_manager_client

	dolib.so "${OUT}"/lib/libtpm_manager.so

	# Install header files.
	insinto /usr/include/tpm_manager/client
	doins ./*.h
	insinto /usr/include/tpm_manager/common
	doins ../common/*.h
	doins "${OUT}"/gen/tpm_manager/common/*.h
}

platform_pkg_test() {
	local tests=(
		tpm_manager-client_testrunner
	)

	local test_bin
	for test_bin in "${tests[@]}"; do
		platform_test "run" "${OUT}/${test_bin}"
	done
}
