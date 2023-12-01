# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_COMMIT="4f101ed59bd0f44ac78eee57f5f87b7006283c30"
CROS_WORKON_TREE=("5f52f55a4678653b15e0126bf489a8e105f32768" "6648df105f2cdf88dc130ef37129760bc02a2ae1" "b62ae50ed547d76feb94710f8c187f5a3f52bc84" "107a6cd74aed39f6f893462ca9099d2f3373347c" "f91b6afd5f2ae04ee9a2c19109a3a4a36f7659e6" "a73d61848554d649c817f4a478d81699119fbc30" "f9bfc14acd64a3f2de62a55467fe65a50b270dba" "af42858f0c4f3fae729c03bccb4e1eb13c295957" "9eb0447b58aa5f1a7f0cb1c8b3adb750f97e5a9f" "0996cdb96b7e23a7fc1d030da6b92dca17edf6ba" "4e7145b8ea4d052efc366039de9242a539c8dc32" "38f0741414429f7fbdcfb7f23dfa0d53a9f7ba19" "dc3c9db3d984574e13865d725f505035d6cac081" "0830dc7ffcbe4f21c9b24856eabf9b6b750648f0" "e6bd3900f555e26548ecc69ae1c7347b9406b1b8" "ee7a391100d5bf60f65682988029562ee9c82798" "4f9e997c7cfc37f43a50de4fe1749cc5c93fa102" "e7484fcabff8350254feec93c24db8c75bdc4965" "32a4c9aa5d67daa8e92c0435ab1fdb64fc85438c" "c1ed260766cf73beeb86cb03f8b90f0ec1042810" "76d848e95fbd8b4f1e5e79c97cf77eda442b4ba7" "0c4a08a4f57b5d6806df4ad5cec9d2c8fb02fab0" "f10a0621aea0aaab45be3a838d5b7782bd35f5c0" "0f8ac67491f7a52e0de6999644a3797b7fed364c" "57dcbeb4c073f8510e8b35cecdf20b000cab5fdb")
CROS_WORKON_LOCALNAME="platform2"
CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_OUTOFTREE_BUILD=1
CROS_WORKON_INCREMENTAL_BUILD=1

PLATFORM2_PATHS=(
	common-mk
	featured
	metrics
	net-base
	.gn
	spaced
	libcrossystem

	vm_tools/BUILD.gn
	vm_tools/host
	vm_tools/common

	vm_tools/cicerone
	vm_tools/concierge
	vm_tools/dbus_bindings
	vm_tools/dbus
	vm_tools/init
	vm_tools/maitred/client.cc
	vm_tools/modprobe
	vm_tools/pstore_dump
	vm_tools/seneschal
	vm_tools/syslog
	vm_tools/tmpfiles.d
	vm_tools/udev
	vm_tools/vsh

	# Required by the fuzzer
	vm_tools/OWNERS

	# Required by the vm_concierge
	chromeos-config
)
CROS_WORKON_SUBTREE="${PLATFORM2_PATHS[*]}"

PLATFORM_SUBDIR="vm_tools"

inherit tmpfiles cros-workon platform udev user arc-build-constants

DESCRIPTION="VM host tools for Chrome OS"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/vm_tools"

LICENSE="BSD-Google"
KEYWORDS="*"
# The crosvm-wl-dmabuf and crosvm-virtio-video USE flags
# are used when preprocessing concierge source.
IUSE="+kvm_host +seccomp +crosvm-wl-dmabuf fuzzer wilco +crosvm-virtio-video vulkan libglvnd virtgpu_native_context cross_domain_context iioservice vfio_gpu arcvm_gki borealis_host"
REQUIRED_USE="kvm_host"

COMMON_DEPEND="
	app-arch/libarchive:=
	!!chromeos-base/vm_tools
	chromeos-base/chunnel:=
	chromeos-base/chromeos-config-tools:=
	chromeos-base/crosvm:=
	chromeos-base/libcrossystem:=
	>=chromeos-base/metrics-0.0.1-r3617:=
	chromeos-base/minijail:=
	chromeos-base/net-base:=
	chromeos-base/patchpanel:=
	chromeos-base/patchpanel-client:=
	chromeos-base/spaced
	net-libs/grpc:=
	dev-libs/protobuf:=
	sys-apps/util-linux:=
"

RDEPEND="
	${COMMON_DEPEND}
	dev-rust/s9
	borealis_host? ( chromeos-base/shadercached:= )
"
DEPEND="
	${COMMON_DEPEND}
	chromeos-base/dlcservice-client:=
	chromeos-base/featured:=
	chromeos-base/session_manager-client:=
	chromeos-base/shill-client:=
	chromeos-base/system_api:=[fuzzer?]
	chromeos-base/vboot_reference:=
	chromeos-base/vm_protos:=
	fuzzer? ( dev-libs/libprotobuf-mutator:= )
"

get_vmlog_forwarder_start_services() {
	local start_services="starting vm_concierge"
	if use wilco; then
		start_services+=" or starting wilco_dtc_dispatcher"
	fi
	echo "${start_services}"
}

get_vmlog_forwarder_stop_services() {
	local stop_services="stopped vm_concierge"
	if use wilco; then
		stop_services="stopping system-services"
	fi
	echo "${stop_services}"
}

pkg_setup() {
	# Duplicated from the crosvm ebuild. These are necessary here in order
	# to create the daemon-store folder for concierge in src_install().
	enewuser crosvm
	enewgroup crosvm
	enewuser pluginvm
	cros-workon_pkg_setup

	enewuser crosvm-root
	enewgroup crosvm-root
}

src_install() {
	platform_src_install

	dobin "${OUT}"/cicerone_client
	dobin "${OUT}"/maitred_client
	dobin "${OUT}"/seneschal
	dobin "${OUT}"/seneschal_client
	dobin "${OUT}"/vm_cicerone
	dobin "${OUT}"/vm_concierge
	dobin "${OUT}"/vmlog_forwarder
	dobin "${OUT}"/vsh

	if use arcvm; then
		dobin "${OUT}"/vm_pstore_dump
		dobin "${OUT}"/vshd
	fi

	# fuzzer_component_id is unknown/unlisted
	platform_fuzzer_install "${S}"/OWNERS "${OUT}"/cicerone_container_listener_fuzzer
	platform_fuzzer_install "${S}"/OWNERS "${OUT}"/vsh_client_fuzzer

	# Install header for passing USB devices to plugin VMs.
	insinto /usr/include/vm_concierge
	doins concierge/plugin_vm_usb.h

	insinto /etc/init
	doins init/seneschal.conf
	doins init/vm_cicerone.conf
	doins init/vm_concierge.conf

	dotmpfiles tmpfiles.d/*.conf

	# Modify vmlog_forwarder starting and stopping conditions based on USE flags.
	sed \
		"-e s,@dependent_start_services@,$(get_vmlog_forwarder_start_services),"\
		"-e s,@dependent_stop_services@,$(get_vmlog_forwarder_stop_services)," \
		init/vmlog_forwarder.conf.in | newins - vmlog_forwarder.conf

	insinto /etc/dbus-1/system.d
	doins dbus/*.conf

	if use vfio_gpu; then
		insinto /etc/modprobe.d
		doins modprobe/vfio-dgpu.conf

		exeinto /sbin
		doexe modprobe/dgpu.sh

		# Udev rules to bind dGPU to different modules.
		udev_dorules udev/45-vfio-dgpu.rules
	fi

	insinto /usr/local/vms/etc
	doins init/arcvm_dev.conf

	# TODO(b/159953121): File and steps below should be removed later.
	insinto /etc
	newins init/arcvm_dev.conf_deprecated arcvm_dev.conf

	insinto /usr/share/policy
	if use seccomp; then
		newins "init/vm_cicerone-seccomp-${ARCH}.policy" vm_cicerone-seccomp.policy
	fi

	udev_dorules udev/99-vm.rules

	keepdir /opt/google/vms

	# Create daemon store folder for crosvm and pvm
	local crosvm_store="/etc/daemon-store/crosvm"
	dodir "${crosvm_store}"
	fperms 0750 "${crosvm_store}"
	fowners crosvm:crosvm "${crosvm_store}"

	local pvm_store="/etc/daemon-store/pvm"
	dodir "${pvm_store}"
	fperms 0770 "${pvm_store}"
	fowners pluginvm:crosvm "${pvm_store}"
}

platform_pkg_test() {
	local tests=(
		cicerone_test
		concierge_test
		syslog_forwarder_test
		vsh_test
	)
	if use arcvm; then
		tests+=(
			vm_pstore_dump_test
		)
	fi

	# Running a gRPC server under qemu-user causes flake, at least with the
	# combination of gRPC 1.16.1 and qemu 3.0.0. Disable TerminaVmTest.* while
	# running under qemu to avoid triggering this flake.
	# TODO(crbug.com/1066425): Reenable gRPC server tests under qemu-user.
	local qemu_gtest_filter="-TerminaVmTest.*"
	local test_bin
	for test_bin in "${tests[@]}"; do
		platform_test "run" "${OUT}/${test_bin}" "0" "" "${qemu_gtest_filter}"
	done
}

pkg_preinst() {
	# We need the syslog user and group for both host and guest builds.
	enewuser syslog
	enewgroup syslog

	enewuser vm_cicerone
	enewgroup vm_cicerone

	enewuser seneschal
	enewgroup seneschal
	enewuser seneschal-dbus
	enewgroup seneschal-dbus

	enewuser pluginvm
	enewgroup pluginvm

	enewgroup virtaccess
}
