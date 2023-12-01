# Copyright 2014 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_LOCALNAME="platform2"
CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_DESTDIR="${S}/platform2"
CROS_WORKON_INCREMENTAL_BUILD=1
# TODO(crbug.com/809389): Avoid directly including headers from other packages.
CROS_WORKON_SUBTREE="common-mk cryptohome libcrossystem libhwsec libhwsec-foundation secure_erase_file .gn"

PLATFORM_NATIVE_TEST="yes"
PLATFORM_SUBDIR="cryptohome"

inherit tmpfiles cros-workon cros-unibuild platform systemd udev user

DESCRIPTION="Encrypted home directories for Chromium OS"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/cryptohome/"
SRC_URI=""

LICENSE="BSD-Google"
SLOT="0/0"
KEYWORDS="~*"
IUSE="+device_mapper -direncription_allow_v2 -direncryption
	double_extend_pcr_issue +downloads_bind_mount fuzzer
	generic_tpm2 kernel-6_1 kernel-5_15 kernel-5_10 kernel-5_4 kernel-upstream
	lvm_application_containers lvm_stateful_partition mount_oop pinweaver
	profiling selinux slow_mount systemd test tpm tpm_dynamic tpm_insecure_fallback tpm2
	tpm2_simulator uprev-4-to-5 user_session_isolation uss_migration
	+vault_legacy_mount vtpm_proxy"

REQUIRED_USE="
	device_mapper
	tpm_dynamic? ( tpm tpm2 )
	!tpm_dynamic? ( ?? ( tpm tpm2 ) )
"

COMMON_DEPEND="
	!chromeos-base/chromeos-cryptohome
	tpm? (
		app-crypt/trousers:=
	)
	fuzzer? (
		app-crypt/trousers:=
	)
	tpm2? (
		chromeos-base/trunks:=
	)
	selinux? (
		sys-libs/libselinux:=
		chromeos-base/selinux-policy:=
	)
	chromeos-base/attestation:=
	chromeos-base/biod_proxy:=
	chromeos-base/bootlockbox-client:=
	chromeos-base/cbor:=
	chromeos-base/chaps:=
	chromeos-base/chromeos-config-tools:=
	chromeos-base/featured:=
	chromeos-base/libhwsec:=[test?]
	>=chromeos-base/metrics-0.0.1-r3152:=
	chromeos-base/secure-erase-file:=
	chromeos-base/tpm_manager:=
	>=dev-libs/flatbuffers-2.0.0-r1:=
	dev-libs/openssl:=
	dev-libs/protobuf:=
	sys-apps/flashmap:=
	sys-apps/keyutils:=
	sys-apps/rootdev:=
	sys-fs/e2fsprogs:=
	sys-fs/ecryptfs-utils:=
	sys-fs/lvm2:=
"

RDEPEND="${COMMON_DEPEND}"

# TODO(b/230430190): Remove shill-client dependency after experiment ended.
DEPEND="${COMMON_DEPEND}
	test? (
		app-shells/dash:=
		chromeos-base/chromeos-base:=
	)
	tpm2? ( chromeos-base/trunks:=[test?] )
	chromeos-base/attestation-client:=
	chromeos-base/cryptohome-client:=
	chromeos-base/libcrossystem:=
	chromeos-base/power_manager-client:=
	chromeos-base/protofiles:=
	chromeos-base/shill-client:=
	chromeos-base/system_api:=[fuzzer?]
	chromeos-base/tpm_manager-client:=
	chromeos-base/vboot_reference:=
	chromeos-base/libhwsec:=
"

src_install() {
	# TODO(crbug/1184602): Move remaining install logic to GN.
	platform_src_install

	pushd "${OUT}" || die
	dosbin cryptohomed cryptohome cryptohome-path homedirs_initializer \
		lockbox-cache stateful-recovery
	dosbin cryptohome-namespace-mounter
	dosbin mount-encrypted
	dosbin encrypted-reboot-vault
	popd >/dev/null || die

	insinto /etc/dbus-1/system.d
	doins etc/org.chromium.UserDataAuth.conf

	if use direncription_allow_v2 && ( (use !kernel-5_4 && use !kernel-5_10 && use !kernel-5_15 && use !kernel-6_1 && use !kernel-upstream) || use uprev-4-to-5); then
		die "direncription_allow_v2 is enabled where it shouldn't be. Do you need to change the board overlay? Note, uprev boards should have it disabled!"
	fi

	if use !direncription_allow_v2 && (use kernel-5_4 || use kernel-5_10 || use kernel-5_15 || use kernel-6_1 || use kernel-upstream) && use !uprev-4-to-5; then
		die "direncription_allow_v2 is not enabled where it should be. Do you need to change the board overlay? Note, uprev boards should have it disabled!"
	fi

	# Install init scripts
	if use systemd; then
		if use tpm2; then
			sed 's/tcsd.service/attestationd.service/' \
				init/cryptohomed.service \
				> "${T}/cryptohomed.service"
			systemd_dounit "${T}/cryptohomed.service"
		else
			systemd_dounit init/cryptohomed.service
		fi
		systemd_dounit init/mount-encrypted.service
		systemd_dounit init/lockbox-cache.service
		systemd_enable_service boot-services.target cryptohomed.service
		systemd_enable_service system-services.target mount-encrypted.service
		systemd_enable_service ui.target lockbox-cache.service
	else
		insinto /etc/init
		doins init/cryptohomed-client.conf
		doins init/cryptohomed.conf
		doins init/init-homedirs.conf
		doins init/mount-encrypted.conf
		doins init/send-mount-encrypted-metrics.conf
		if use tpm_dynamic; then
			newins init/lockbox-cache.conf.tpm_dynamic lockbox-cache.conf
		else
			doins init/lockbox-cache.conf
		fi

		if use direncryption; then
			sed -i '/env DIRENCRYPTION_FLAG=/s:=.*:="--direncryption":' \
				"${D}/etc/init/cryptohomed.conf" ||
				die "Can't replace direncryption flag in cryptohomed.conf"
		fi
		if use !vault_legacy_mount; then
			sed -i '/env NO_LEGACY_MOUNT_FLAG=/s:=.*:="--nolegacymount":' \
				"${D}/etc/init/cryptohomed.conf" ||
				die "Can't replace nolegacymount flag in cryptohomed.conf"
		fi
		if use !downloads_bind_mount; then
			sed -i '/env NO_DOWNLOAD_BINDMOUNT_FLAG=/s:=.*:="--no_downloads_bind_mount":' \
				"${D}/etc/init/cryptohomed.conf" ||
				die "Can't replace no_downloads_bind_mount flag in cryptohomed.conf"
		fi
		if use direncription_allow_v2; then
			sed -i '/env FSCRYPT_V2_FLAG=/s:=.*:="--fscrypt_v2":' \
				"${D}/etc/init/cryptohomed.conf" ||
				die "Can't replace fscrypt_v2 flag in cryptohomed.conf"
		fi
		if use lvm_application_containers; then
			sed -i '/env APPLICATION_CONTAINERS=/s:=.*:="--application_containers":' \
				"${D}/etc/init/cryptohomed.conf" ||
				die "Can't replace application_containers flag in cryptohomed.conf"
		fi
	fi
	exeinto /usr/share/cros/init
	if use tpm_dynamic; then
		newexe init/lockbox-cache.sh.tpm_dynamic lockbox-cache.sh
	else
		doexe init/lockbox-cache.sh
	fi

	# Install udev rules for cryptohome.
	udev_dorules udev/50-dm-cryptohome.rules

	dotmpfiles tmpfiles.d/cryptohome.conf

	local fuzzer_component_id="1088399"
	platform_fuzzer_install "${S}"/OWNERS \
		"${OUT}"/cryptohome_cryptolib_blob_to_hex_fuzzer \
		--comp "${fuzzer_component_id}"

	platform_fuzzer_install "${S}"/OWNERS \
		"${OUT}"/cryptohome_userdataauth_fuzzer \
		--comp "${fuzzer_component_id}"

	platform_fuzzer_install "${S}"/OWNERS \
		"${OUT}"/cryptohome_user_secret_stash_parser_fuzzer \
		--comp "${fuzzer_component_id}"

	platform_fuzzer_install "${S}"/OWNERS \
		"${OUT}"/cryptohome_recovery_id_fuzzer \
		--comp "${fuzzer_component_id}"
}

pkg_preinst() {
	enewuser "cryptohome"
	enewgroup "cryptohome"
}

platform_pkg_test() {
	platform_test "run" "${OUT}/cryptohome_testrunner"
	platform_test "run" "${OUT}/fake_platform_unittest"
	platform_test "run" "${OUT}/mount_encrypted_unittests"
	platform_test "run" "${OUT}/stateful_recovery_unittests"
}
