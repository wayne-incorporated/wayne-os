# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

# This ebuild only cares about its own FILESDIR and ebuild file, so it tracks
# the canonical empty project.
CROS_WORKON_PROJECT="chromiumos/infra/build/empty-project"
CROS_WORKON_LOCALNAME="platform/empty-project"

inherit cros-workon

DESCRIPTION="Text file listing USE flags for Tast test dependencies"

LICENSE="BSD-Google"
# Nothing depends on this package for build info.  All the files are used at
# runtime only by design.
SLOT="0/0"
KEYWORDS="~*"

# NB: Flags listed here are off by default unless prefixed with a '+'.
IUSE="
	amd64
	amd_cpu
	android-container-pi
	android-container-rvc
	android-vm-pi
	android-vm-rvc
	android-vm-tm
	arc
	arc-camera3
	arc-launched-32bit-abi
	arcpp
	arcvm
	arcvm_data_migration
	arcvm_virtio_blk_data
	arm
	arm64
	asan
	betty
	biod
	downloads_bind_mount
	borealis_host
	borealis_nvidia
	camera_feature_auto_framing
	camera_feature_effects
	camera_feature_hdrnet
	camera_feature_portrait_mode
	cdm_factory_daemon
	cert_provision
	cheets_user
	cheets_user_64
	cheets_userdebug
	cheets_userdebug_64
	chrome_dcheck
	chrome_internal
	chrome_media
	chromeless_tty
	chromeos_kernelci_builder
	clvk
	containers
	cr50_onboard
	+cras
	crosvm-gpu
	crosvm-swap
	cups
	diagnostics
	disable_cros_video_decoder
	dptf
	elm-kernelnext
	direncription_allow_v2
	dlc
	dlc_test
	+drivefs
	drm_atomic
	elm
	faceauth
	fizz
	flex_id
	force_breakpad
	fwupd
	grunt
	hammerd
	hana
	hana-kernelnext
	houdini
	houdini64
	hps
	iioservice
	inference_accuracy_eval
	internal
	iwlwifi_rescan
	kernel-4_4
	kernel-4_14
	kernel-4_19
	kernel-5_4
	kernel-5_10
	kernel-5_15
	kernel-6_1
	kernel-upstream
	kukui
	kvm_host
	lvm_stateful_partition
	lxc
	+mbo
	memd
	ml_benchmark_drivers
	ml_service
	moblab
	mocktpm
	modemfwd
	msan
	+nacl
	ndk_translation
	ndk_translation64
	nnapi
	no_factory_flow
	nvme
	nyan_kitty
	ocr
	octopus
	ondevice_document_scanner
	ondevice_document_scanner_dlc
	ondevice_grammar
	ondevice_handwriting
	ondevice_speech
	ondevice_text_suggestions
	pinweaver_csme
	pita
	postscript
	printscanmgr
	racc
	rialto
	rk3399
	sata
	selinux
	selinux_experimental
	sirenia
	skate
	smartdim
	snow
	spring
	+storage_wearout_detect
	tablet_form_factor
	ti50_onboard
	tpm
	tpm2
	tpm2_simulator
	tpm_dynamic
	transparent_hugepage
	ubsan
	unibuild
	usbguard
	v4l2_codec
	vaapi
	veyron_mickey
	veyron_rialto
	video_cards_amdgpu
	video_cards_iHD
	video_cards_intel
	video_cards_mediatek
	video_cards_msm
	virtio_gpu
	vkms
	vulkan
	watchdog
	wifi_hostap_test
	wilco
	+wpa3_sae
	zork
"

src_install() {
	# Install a file containing a list of currently-set USE flags.
	local path="${WORKDIR}/tast_use_flags.txt"
	cat <<EOF >"${path}"
# This file is used by the Tast integration testing system to
# determine which software features are present in the system image.
# Don't use it for anything else. Your code will break.
EOF

	# If you need to inspect a new flag, add it to $IUSE at the top of the file.
	# shellcheck disable=SC2206
	local flags=( ${IUSE} )
	local flag
	for flag in "${flags[@]/#[-+]}" ; do
		usev "${flag}"
	done | sort -u >>"${path}"

	insinto /etc
	doins "${path}"
}
