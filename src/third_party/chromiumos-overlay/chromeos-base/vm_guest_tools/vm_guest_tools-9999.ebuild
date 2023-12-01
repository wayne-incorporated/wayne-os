# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_LOCALNAME="platform2"
CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_OUTOFTREE_BUILD=1
CROS_WORKON_INCREMENTAL_BUILD=1

PLATFORM2_PATHS=(
	common-mk
	.gn

	vm_tools/BUILD.gn
	vm_tools/guest
	vm_tools/common

	vm_tools/demos
	vm_tools/garcon
	vm_tools/guest_service_failure_notifier
	vm_tools/maitred
	vm_tools/notificationd
	vm_tools/sommelier
	vm_tools/syslog
	vm_tools/upgrade_container
	vm_tools/virtwl_guest_proxy
	vm_tools/vsh

	# Required by the fuzzer
	vm_tools/OWNERS
	vm_tools/testdata
)
CROS_WORKON_SUBTREE="${PLATFORM2_PATHS[*]}"

PLATFORM_SUBDIR="vm_tools"

inherit cros-go cros-workon platform user

DESCRIPTION="VM guest tools for Chrome OS"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/vm_tools"

LICENSE="BSD-Google"
KEYWORDS="~*"
IUSE="kvm_guest vm-containers fuzzer vm_borealis vm_sludge"

# This ebuild should only be used on VM guest boards.
REQUIRED_USE="kvm_guest"

COMMON_DEPEND="
	!!chromeos-base/vm_tools
	chromeos-base/minijail:=
	net-libs/grpc:=
	dev-libs/protobuf:=
	dev-go/protobuf-legacy-api:=
"

RDEPEND="
	${COMMON_DEPEND}
	vm-containers? (
		chromeos-base/crash-reporter
		chromeos-base/crostini-metric-reporter
	)
	!fuzzer? (
		chromeos-base/sommelier
	)
"

DEPEND="
	${COMMON_DEPEND}
	dev-go/grpc:=
	dev-go/protobuf:=
	sys-kernel/linux-headers:=
	chromeos-base/vm_protos:=
"

src_install() {
	platform_src_install

	dobin "${OUT}"/vm_syslog
	dosbin "${OUT}"/vshd

	if use vm-containers || use vm_borealis; then
		dobin "${OUT}"/garcon
	fi
	if use vm-containers; then
		dobin "${OUT}"/guest_service_failure_notifier
		dobin "${OUT}"/notificationd
		dobin "${OUT}"/upgrade_container
		dobin "${OUT}"/virtwl_guest_proxy
		dobin "${OUT}"/wayland_demo
		dobin "${OUT}"/x11_demo
	fi

	# fuzzer_component_id is unknown/unlisted
	platform_fuzzer_install "${S}"/OWNERS "${OUT}"/garcon_desktop_file_fuzzer \
		--dict "${S}"/testdata/garcon_desktop_file_fuzzer.dict
	platform_fuzzer_install "${S}"/OWNERS "${OUT}"/garcon_icon_index_file_fuzzer \
		--dict "${S}"/testdata/garcon_icon_index_file_fuzzer.dict
	platform_fuzzer_install "${S}"/OWNERS "${OUT}"/garcon_ini_parse_util_fuzzer
	platform_fuzzer_install "${S}"/OWNERS "${OUT}"/garcon_mime_types_parser_fuzzer

	dobin "${OUT}"/maitred
	dosym /usr/bin/maitred /sbin/init

	# Create a folder for process configs to be launched at VM startup.
	dodir /etc/maitred/

	use fuzzer || dosym /run/resolv.conf /etc/resolv.conf

	CROS_GO_WORKSPACE="${OUT}/gen/go"
	cros-go_src_install
}

platform_pkg_test() {
	local tests=(
		maitred_init_test
		maitred_service_test
		maitred_syslog_test
	)

	local container_tests=(
		garcon_desktop_file_test
		garcon_icon_index_file_test
		garcon_icon_finder_test
		garcon_mime_types_parser_test
		notificationd_test
	)

	if use vm-containers || use vm_borealis; then
		tests+=( "${container_tests[@]}" )
	fi

	local test_bin
	for test_bin in "${tests[@]}"; do
		platform_test "run" "${OUT}/${test_bin}"
	done
}

pkg_preinst() {
	# We need the syslog user and group for both host and guest builds.
	enewuser syslog
	enewgroup syslog
}
