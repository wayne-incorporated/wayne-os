# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

CROS_WORKON_INCREMENTAL_BUILD=1
CROS_WORKON_LOCALNAME="platform2"
CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_DESTDIR="${S}/platform2"
CROS_WORKON_SUBTREE="common-mk typecd .gn"

PLATFORM_SUBDIR="typecd"

inherit cros-workon platform user

DESCRIPTION="Chrome OS USB Type C daemon"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/typecd/"

LICENSE="BSD-Google"
SLOT=0
KEYWORDS="~*"
IUSE="+seccomp"

RDEPEND=">=chromeos-base/metrics-0.0.1-r3152:="

DEPEND="
	${RDEPEND}
	chromeos-base/debugd-client:=
	chromeos-base/session_manager-client:=
	chromeos-base/system_api:=
"

src_install() {
	platform_src_install

	dobin "${OUT}"/typecd
	dobin "${OUT}"/typecd_tool

	insinto /usr/share/dbus-1/system-services
	doins dbus/org.chromium.typecd.service

	insinto /etc/init
	doins init/*.conf

	# Install seccomp policy files.
	insinto /usr/share/policy
	if use seccomp; then
		newins "seccomp/typecd-seccomp-${ARCH}.policy" typecd-seccomp.policy
		newins "seccomp/ectool_typec-seccomp-${ARCH}.policy" ectool_typec-seccomp.policy
	fi

	# Install rsyslog config.
	insinto /etc/rsyslog.d
	doins rsyslog/rsyslog.typecd.conf

	# Install D-Bus permission config.
	insinto /etc/dbus-1/system.d
	doins dbus/typecd.conf

	# Install fuzzers.
	local fuzzer_component_id="958036"
	local fuzz_targets=(
		"typecd_cable_fuzzer"
		"typecd_cros_ec_util_fuzzer"
		"typecd_partner_fuzzer"
		"typecd_port_fuzzer"
		"typecd_port_manager_fuzzer"
		"typecd_session_manager_proxy_fuzzer"
		"typecd_udev_monitor_fuzzer"
	)
	local fuzz_target
	for fuzz_target in "${fuzz_targets[@]}"; do
		platform_fuzzer_install "${S}"/OWNERS "${OUT}"/"${fuzz_target}" \
			--comp "${fuzzer_component_id}"
	done
}

pkg_preinst() {
	enewuser typecd
	enewgroup typecd

	# This group is required for debugd EC Type C tool to access /dev/cros_ec.
	enewgroup cros_ec-access
	# Add user and group for debugd Type C commands.
	enewuser typecd_ec
	enewgroup typecd_ec
}

platform_pkg_test() {
	platform_test "run" "${OUT}/typecd_testrunner"
}
