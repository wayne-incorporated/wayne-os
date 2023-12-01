# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_COMMIT="5a40186abf3a23ed8707d6cef25112167eabaede"
CROS_WORKON_TREE=("5f52f55a4678653b15e0126bf489a8e105f32768" "57dcbeb4c073f8510e8b35cecdf20b000cab5fdb" "e5213f48c6ed0dcfb7d1410f706196c31c5dbb40" "0a25fb794e3f4f6bef7c6e9e007a9a477f145fbe" "88bfaa73f3073fc4c5b9560b5963734b7215af0d" "4e2cac5adeeeb372be7aaa3c4f317230a7652ae8" "f91b6afd5f2ae04ee9a2c19109a3a4a36f7659e6")
CROS_WORKON_INCREMENTAL_BUILD="1"
CROS_WORKON_LOCALNAME="platform2"
CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_OUTOFTREE_BUILD=1
# TODO(crbug.com/809389): Remove libmems from this list.
CROS_WORKON_SUBTREE="common-mk chromeos-config iioservice mems_setup libmems libsar .gn"

PLATFORM_SUBDIR="mems_setup"

inherit cros-workon cros-unibuild platform udev

DESCRIPTION="MEMS Setup for Chromium OS."
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/mems_setup"

LICENSE="BSD-Google"
KEYWORDS="*"
IUSE="fuzzer"

COMMON_DEPEND="
	chromeos-base/chromeos-config-tools:=
	chromeos-base/libmems:=
	chromeos-base/libsar:=
	net-libs/libiio:=
	dev-libs/re2:=
"

RDEPEND="${COMMON_DEPEND}"

DEPEND="${COMMON_DEPEND}
	chromeos-base/system_api:="

src_install() {
	udev_dorules 99-mems_setup.rules
	platform_src_install

	# Install fuzzers
	local fuzzer_component_id="811602"
	insinto /usr/libexec/fuzzers
	for fuzzer in "${OUT}"/*_fuzzer; do
		platform_fuzzer_install "${S}"/OWNERS "${fuzzer}" \
				--comp "${fuzzer_component_id}"
	done
}

platform_pkg_test() {
	platform test_all
}
