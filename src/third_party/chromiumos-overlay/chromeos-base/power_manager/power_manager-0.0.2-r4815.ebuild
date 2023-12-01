# Copyright 2014 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7
CROS_WORKON_COMMIT="6246f89515ecf16f8ad925520c1eb6b8f831edfe"
CROS_WORKON_TREE=("5f52f55a4678653b15e0126bf489a8e105f32768" "57dcbeb4c073f8510e8b35cecdf20b000cab5fdb" "6648df105f2cdf88dc130ef37129760bc02a2ae1" "e5213f48c6ed0dcfb7d1410f706196c31c5dbb40" "d16b1fd4678bacbab13664cbd6d07acee4cca695" "b62ae50ed547d76feb94710f8c187f5a3f52bc84" "66d9ece0c55ff21826b4962ffd402f0927467387" "f0ecb2d293b7925a93d6f9845049353267cac4bc" "f74f32e76e5f0463b8473657c06db9cbb493b16a" "f91b6afd5f2ae04ee9a2c19109a3a4a36f7659e6")
CROS_WORKON_USE_VCSID="1"
CROS_WORKON_LOCALNAME="platform2"
CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_OUTOFTREE_BUILD=1
# TODO(crbug.com/809389): Avoid directly including headers from other packages.
CROS_WORKON_SUBTREE="common-mk chromeos-config featured iioservice libec metrics mojo_service_manager power_manager shill/dbus/client .gn"

PLATFORM_NATIVE_TEST="yes"
PLATFORM_SUBDIR="power_manager"

inherit tmpfiles cros-workon cros-unibuild platform systemd udev user

DESCRIPTION="Power Manager for Chromium OS"
HOMEPAGE="http://dev.chromium.org/chromium-os/packages/power_manager"

LICENSE="BSD-Google"
KEYWORDS="*"
IUSE="-als cellular +cras cros_embedded +display_backlight fuzzer -has_keyboard_backlight iioservice -keyboard_includes_side_buttons keyboard_convertible_no_side_buttons -legacy_power_button -powerd_manual_eventlog_add +powerknobs systemd +touchpad_wakeup -touchscreen_wakeup unibuild wilco qrtr"
REQUIRED_USE="
	?? ( keyboard_includes_side_buttons keyboard_convertible_no_side_buttons )"

COMMON_DEPEND="
	chromeos-base/chromeos-config-tools:=
	chromeos-base/featured:=
	chromeos-base/libec:=
	chromeos-base/libiioservice_ipc:=
	>=chromeos-base/metrics-0.0.1-r3152:=
	chromeos-base/ml-client:=
	chromeos-base/mojo_service_manager:=
	chromeos-base/power_manager-client:=
	chromeos-base/shill-dbus-client:=
	chromeos-base/tpm_manager-client:=
	dev-libs/libnl:=
	dev-libs/protobuf:=
	dev-libs/re2:=
	cras? ( media-sound/adhd:= )
	virtual/udev
	cellular? ( net-misc/modemmanager-next:= )"

RDEPEND="${COMMON_DEPEND}
	chromeos-base/libiioservice_ipc:=
	powerd_manual_eventlog_add? ( sys-apps/coreboot-utils )
	qrtr? ( net-libs/libqrtr:= )
"

DEPEND="${COMMON_DEPEND}
	chromeos-base/chromeos-ec-headers:=
	chromeos-base/system_api:=[fuzzer?]
	qrtr? ( sys-apps/upstart:= )
"

pkg_setup() {
	# Create the 'power' user and group here in pkg_setup as src_install needs
	# them to change the ownership of power manager files.
	enewuser "power"
	enewgroup "power"
	# Ensure that this group exists so that power_manager can access
	# /dev/cros_ec.
	enewgroup "cros_ec-access"
	cros-workon_pkg_setup
}

src_install() {
	platform_src_install

	# Binaries for production
	dobin "${OUT}"/backlight_tool  # boot-splash, chromeos-boot-alert
	dobin "${OUT}"/cpufreq_config
	dobin "${OUT}"/dump_power_status  # crosh's battery_test command
	dobin "${OUT}"/powerd
	dobin "${OUT}"/powerd_setuid_helper
	dobin "${OUT}"/power_supply_info  # feedback
	dobin "${OUT}"/set_cellular_transmit_power
	dobin "${OUT}"/set_wifi_transmit_power
	fowners root:power /usr/bin/powerd_setuid_helper
	fperms 4750 /usr/bin/powerd_setuid_helper

	# Binaries for testing and debugging
	dobin "${OUT}"/battery_saver
	dobin "${OUT}"/check_powerd_config
	use amd64 && dobin "${OUT}"/dump_intel_rapl_consumption
	dobin "${OUT}"/inject_powerd_input_event
	dobin "${OUT}"/memory_suspend_test
	dobin "${OUT}"/powerd_dbus_reboot
	dobin "${OUT}"/powerd_dbus_shutdown
	dobin "${OUT}"/powerd_dbus_suspend
	dobin "${OUT}"/send_debug_power_status
	dobin "${OUT}"/set_power_policy
	dobin "${OUT}"/suspend_delay_sample

	# Scripts for production
	dobin powerd/powerd_suspend
	dobin tools/print_sysfs_power_supply_data  # feedback
	dobin tools/send_metrics_on_resume
	dobin tools/thermal_zone_config

	# Scripts for testing and debugging
	dobin tools/activate_short_dark_resume
	dobin tools/debug_sleep_quickly
	dobin tools/set_short_powerd_timeouts
	dobin tools/suspend_stress_test

	# Scripts called from init scripts
	exeinto /usr/share/cros/init/
	doexe tools/temp_logger.sh

	# Preferences
	insinto /usr/share/power_manager
	doins default_prefs/*
	use als && doins optional_prefs/has_ambient_light_sensor
	use cras && doins optional_prefs/use_cras
	use display_backlight || doins optional_prefs/external_display_only
	use has_keyboard_backlight && doins optional_prefs/has_keyboard_backlight
	use legacy_power_button && doins optional_prefs/legacy_power_button
	use powerd_manual_eventlog_add && doins optional_prefs/manual_eventlog_add

	insinto /etc/dbus-1/system.d
	doins dbus/org.chromium.PowerManager.conf

	# udev scripts and rules.
	exeinto "$(get_udevdir)"
	doexe udev/*.sh
	udev_dorules udev/*.rules

	if use powerknobs; then
		udev/gen_autosuspend_rules.py > "${T}"/98-autosuspend.rules || die
		udev_dorules "${T}"/98-autosuspend.rules
		udev_dorules udev/optional/98-powerknobs.rules
		dobin udev/optional/set_blkdev_pm
	fi
	if use keyboard_includes_side_buttons; then
		udev_dorules udev/optional/93-powerd-tags-keyboard-side-buttons.rules
	elif use keyboard_convertible_no_side_buttons; then
		udev_dorules udev/optional/93-powerd-tags-keyboard-convertible.rules
	fi

	if ! use touchpad_wakeup; then
		udev_dorules udev/optional/93-powerd-tags-no-touchpad-wakeup.rules
	elif use unibuild; then
		udev_dorules udev/optional/93-powerd-tags-unibuild-touchpad-wakeup.rules
	fi

	if use touchscreen_wakeup; then
		udev_dorules udev/optional/93-powerd-tags-touchscreen-wakeup.rules
	elif use unibuild; then
		udev_dorules udev/optional/93-powerd-tags-unibuild-touchscreen-wakeup.rules
	fi

	if use wilco; then
		udev_dorules udev/optional/93-powerd-wilco-ec-files.rules

		exeinto /usr/share/cros/init/optional
		doexe init/shared/optional/powerd-pre-start-wilco.sh
	fi

	# Init scripts
	if use systemd; then
		systemd_dounit init/systemd/*.service
		systemd_enable_service boot-services.target powerd.service
		systemd_enable_service system-services.target report-power-metrics.service
		dotmpfiles init/systemd/powerd_directories.conf
	else
		insinto /etc/init
		doins init/upstart/*.conf
	fi
	exeinto /usr/share/cros/init
	doexe init/shared/powerd-pre-start.sh

	dotmpfiles tmpfiles.d/*.conf

	# Install fuzz targets.
	local fuzzer
	for fuzzer in "${OUT}"/*_fuzzer; do
		local fuzzer_component_id="167191"
		platform_fuzzer_install "${S}"/OWNERS "${fuzzer}" \
			--comp "${fuzzer_component_id}"
	done
}

platform_pkg_test() {
	local tests=(
		power_manager_daemon_test
		power_manager_policy_test
		power_manager_system_test
		power_manager_tools_battery_saver_test
		power_manager_util_test
	)

	local test_bin
	for test_bin in "${tests[@]}"; do
		platform_test "run" "${OUT}/${test_bin}"
	done
}
