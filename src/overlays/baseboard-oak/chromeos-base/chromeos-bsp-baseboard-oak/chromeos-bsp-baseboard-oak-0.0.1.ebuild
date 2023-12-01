# Copyright 2016 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit udev

DESCRIPTION="Ebuild which pulls in any necessary ebuilds as dependencies
or portage actions."

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="-* arm64 arm"
S="${WORKDIR}"
IUSE="cheets kernel-4_4 kernel-4_19 kernel-5_15 mt8176"

# Add dependencies on other ebuilds from within this board overlay
DEPEND="
	!media-libs/media-rules
	net-wireless/marvell_sd8787
"
RDEPEND="${DEPEND}"

src_install() {
	local soc=$(usex mt8176 mt817{6,3})
	local kernel=$(usex kernel-4_4 4_4 3_18)
	kernel=$(usex kernel-4_19 4_19 "${kernel}")
	kernel=$(usex kernel-5_15 5_15 "${kernel}")

	# Install cpuset adjustments.
	insinto "/etc/init"

	if [[ ${kernel} != "5_15" ]]; then
		newins "${FILESDIR}/platform-cpusets-${soc}-${kernel}.conf" platform-cpusets.conf
	fi

	# Install platform specific triggers and udev rules for codecs.
	doins "${FILESDIR}/udev-trigger-codec.conf"
	udev_dorules "${FILESDIR}/50-media.rules"

	# chromeos-4.4 boots using performance governor.
	# After boot switch to sched governor
	if [[ ${kernel} != "3_18" ]]; then
		insinto "/etc"
		doins "${FILESDIR}/cpufreq-${kernel}/cpufreq.conf"
	fi

	if use cheets; then
		insinto "/opt/google/containers/android/vendor/etc/init"
		newins "${FILESDIR}/init.cpusets-${soc}-${kernel}.rc" init.cpusets.rc
	fi
}
