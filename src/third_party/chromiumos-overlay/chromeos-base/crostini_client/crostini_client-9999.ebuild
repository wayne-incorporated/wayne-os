# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"
CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_LOCALNAME="platform2"
CROS_WORKON_SUBTREE="vm_tools/crostini_client"
CROS_WORKON_INCREMENTAL_BUILD=1

inherit cros-workon cros-rust

DESCRIPTION="Command-line client for controlling crostini"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/vm_tools/crostini_client/"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="~*"

BDEPEND="dev-libs/protobuf"
DEPEND="
	chromeos-base/system_api
	cros_host? ( dev-libs/protobuf:= )
	dev-rust/libchromeos:=
	dev-rust/system_api:=
	dev-rust/third-party-crates-src:=
	sys-apps/dbus:=
"

RDEPEND="sys-apps/dbus"

src_unpack() {
	cros-workon_src_unpack
	# The compilation happens in the crostini_client subdirectory.
	S+="/vm_tools/crostini_client"
	cros-rust_src_unpack
}

src_compile() {
	ecargo_build
	use test && ecargo_test --no-run
}

src_test() {
	if ! use x86 && ! use amd64 ; then
		elog "Skipping unit tests on non-x86 platform"
	else
		ecargo_test --all
	fi
}

src_install() {
	local build_dir="$(cros-rust_get_build_dir)"
	dobin "${build_dir}/crostini_client"
	dosym "crostini_client" "/usr/bin/vmc"
}
