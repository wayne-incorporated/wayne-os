# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_COMMIT="1a920e77ed7e53cc6a1bf19b6d77189f38dd922d"
CROS_WORKON_TREE=("5f52f55a4678653b15e0126bf489a8e105f32768" "f91b6afd5f2ae04ee9a2c19109a3a4a36f7659e6" "af42858f0c4f3fae729c03bccb4e1eb13c295957" "81406a32898f310de1ad0fb773c7c66c0d2d59a5" "0996cdb96b7e23a7fc1d030da6b92dca17edf6ba" "f368627960e9d37dd0154fe8655e3370bd2bba38" "82685a5e4cc86367fbcfa4c8b9988ebef9f0a70b" "0c5a113933f1222bcbe43f22d86e947ce021ba47" "78d9c3f8675e8229b3e0a3205ae9dc6e4779de58" "1d9ce187cc73a8cdb8f522eb5163315cac04a557" "b930e15ce5a67307490cb24b10b58505227afd44" "c1ed260766cf73beeb86cb03f8b90f0ec1042810" "363f05d82723f00e35badca3f23b3b75ab52d543" "53d7146a8355184359434857b66bdadeb40b66a1" "f10a0621aea0aaab45be3a838d5b7782bd35f5c0" "0f8ac67491f7a52e0de6999644a3797b7fed364c" "a01dc69a1e1fa54805fe9b48ce5c278a7e70de0c")
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
KEYWORDS="*"
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
